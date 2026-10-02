#!/usr/bin/env python3
"""SA VPN administration. Private state never belongs in the Git repository."""
import argparse
import base64
import copy
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import uuid
from urllib.parse import urlencode, quote

ROOT = Path('/etc/sa-vpn')
WEB = Path('/var/lib/sa-vpn/sub')
XRAY = Path('/etc/sa-vpn/xray.json')


def atomic(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def client(name):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,40}', name):
        raise ValueError('Имя: 1–40 латинских букв, цифр, _ или -')
    return {'name': name, 'id': str(uuid.uuid4()), 'token': secrets.token_hex(24)}


def initial_state(ip, count=1):
    validate_ip(ip)
    if type(count) is not int or not 1 <= count <= 5:
        raise ValueError('Количество ключей: целое число от 1 до 5')
    return {'schema': 1, 'ip': ip, 'path': '/' + secrets.token_hex(16),
            'clients': [client(str(n)) for n in range(1, count + 1)]}


def provision(state, count):
    if type(count) is not int or not 1 <= count <= 5:
        raise ValueError('Количество ключей: целое число от 1 до 5')
    if (ROOT / 'installed').exists():
        raise ValueError('Установка уже завершена; используйте add/revoke')
    expected = [str(n) for n in range(1, len(state['clients']) + 1)]
    if [c['name'] for c in state['clients']] != expected:
        raise ValueError('Существующие именные профили нельзя заменить автоматически')
    changed = copy.deepcopy(state)
    changed['clients'] = changed['clients'][:count]
    changed['clients'].extend(client(str(n)) for n in range(len(changed['clients']) + 1, count + 1))
    return changed


def validate_ip(ip):
    parsed = ipaddress.ip_address(ip)
    if parsed.version != 4 or not parsed.is_global:
        raise ValueError('Нужен публичный IPv4 сервера')


def validate(state):
    if state.get('schema') != 1:
        raise ValueError('Неизвестная версия резервной копии')
    validate_ip(state['ip'])
    if not re.fullmatch(r'/[a-f0-9]{32}', state['path']):
        raise ValueError('Некорректный путь WebSocket')
    names, ids, tokens = set(), set(), set()
    for c in state['clients']:
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,40}', c['name']):
            raise ValueError('Некорректное имя')
        if str(uuid.UUID(c['id'])) != c['id']:
            raise ValueError('Некорректный UUID')
        if not re.fullmatch(r'[a-f0-9]{48}', c['token']):
            raise ValueError('Некорректный токен')
        if c['name'] in names or c['id'] in ids or c['token'] in tokens:
            raise ValueError('Повторяющийся пользователь или ключ')
        names.add(c['name']); ids.add(c['id']); tokens.add(c['token'])


def uri(state, c):
    query = urlencode({'encryption': 'none', 'security': 'tls',
                       'sni': state['ip'], 'type': 'ws', 'path': state['path']})
    return f"vless://{c['id']}@{state['ip']}:443?{query}#{quote('sa-vpn-' + c['name'])}"


def config(state):
    validate(state)
    return {'log': {'loglevel': 'warning', 'access': 'none'},
            'inbounds': [{'listen': '127.0.0.1', 'port': 10000,
                          'protocol': 'vless', 'tag': 'vpn',
                          'settings': {'decryption': 'none', 'clients': [
                              {'id': c['id'], 'email': c['name'], 'flow': ''}
                              for c in state['clients']]},
                          'streamSettings': {'network': 'ws', 'security': 'none',
                                             'wsSettings': {'path': state['path']}}}],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'},
                          {'protocol': 'blackhole', 'tag': 'block'}],
            'routing': {'rules': [{'type': 'field', 'ip': ['geoip:private'],
                                   'outboundTag': 'block'}]}}


def nginx(state, tls=True):
    # No access logs: subscription URLs are credentials.
    http = '''server {
    listen 80;
    server_name _;
    access_log off;
    location ^~ /.well-known/acme-challenge/ { root /var/lib/sa-vpn/acme; }
    location / { return 404; }
}
'''
    if not tls:
        return http
    cert = '/etc/letsencrypt/live/sa-vpn'
    common = f'''    ssl_certificate {cert}/fullchain.pem;
    ssl_certificate_key {cert}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;
    error_log /var/log/nginx/sa-vpn-error.log crit;
'''
    return http + f'''server {{
    listen 443 ssl;
    server_name _;
{common}
    location = {state['path']} {{
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location / {{ return 404; }}
}}
server {{
    listen 2096 ssl;
    server_name _;
{common}
    root /var/lib/sa-vpn;
    location ~ "^/sub/[a-f0-9]{{48}}$" {{
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        try_files $uri =404;
    }}
    location / {{ return 404; }}
}}
'''


def load():
    state = json.loads((ROOT / 'state.json').read_text())
    validate(state)
    return state


def render(state, tls=True):
    validate(state)
    atomic(XRAY, json.dumps(config(state), indent=2) + '\n', 0o640)
    atomic('/etc/nginx/conf.d/sa-vpn.conf', nginx(state, tls), 0o644)
    WEB.mkdir(parents=True, exist_ok=True)
    os.chmod(WEB, 0o755)
    wanted = set()
    for c in state['clients']:
        wanted.add(c['token'])
        body = base64.b64encode((uri(state, c) + '\n').encode()).decode() + '\n'
        atomic(WEB / c['token'], body, 0o644)
    # Only generated subscription files, never unrelated files.
    for file in WEB.iterdir():
        if re.fullmatch(r'[a-f0-9]{48}', file.name) and file.name not in wanted:
            file.unlink()
    subprocess.run(['chown', 'root:sa-vpn', str(XRAY)], check=True)


def run(*args):
    subprocess.run(args, check=True)


def apply(state):
    previous = load()
    validate(state)
    try:
        render(state)
        run('/usr/local/lib/sa-vpn/xray', 'run', '-test', '-config', str(XRAY))
        run('nginx', '-t')
        run('systemctl', 'restart', 'sa-vpn-xray')
        run('systemctl', 'reload', 'nginx')
        atomic(ROOT / 'state.json', json.dumps(state, indent=2) + '\n')
    except Exception:
        render(previous)
        run('systemctl', 'restart', 'sa-vpn-xray')
        run('systemctl', 'reload', 'nginx')
        raise


def links(state):
    for c in state['clients']:
        print(f"\n{c['name']}: https://{state['ip']}:2096/sub/{c['token']}")
        print(uri(state, c))


def backup():
    directory = Path('/var/backups/sa-vpn')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    file = directory / f'{stamp}.tar.gz'
    with tarfile.open(file, 'w:gz') as archive:
        archive.add(ROOT / 'state.json', arcname='state.json')
    os.chmod(file, 0o600)
    print(file)
    return file


def restore(file):
    # Read one bounded JSON member; do not extract untrusted tar paths.
    with tarfile.open(file, 'r:gz') as archive:
        member = archive.getmember('state.json')
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError('Некорректная резервная копия')
        restored = json.load(archive.extractfile(member))
    validate(restored)
    restored['ip'] = load()['ip']
    backup()
    apply(restored)
    links(restored)


def main():
    parser = argparse.ArgumentParser(description='Управление SA VPN')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('links')
    sub.add_parser('backup')
    sub.add_parser('doctor')
    p = sub.add_parser('add'); p.add_argument('name')
    p = sub.add_parser('revoke'); p.add_argument('name')
    p = sub.add_parser('restore'); p.add_argument('archive')
    p = sub.add_parser('init'); p.add_argument('ip')
    p = sub.add_parser('provision'); p.add_argument('count', type=int)
    p = sub.add_parser('render'); p.add_argument('--http-only', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Запустите через sudo или от root')
    if args.command == 'init':
        if (ROOT / 'state.json').exists():
            load()  # Never rotate existing keys on a repeated install.
        else:
            atomic(ROOT / 'state.json', json.dumps(initial_state(args.ip), indent=2) + '\n')
        return
    state = load()
    if args.command == 'links':
        links(state)
    elif args.command == 'backup':
        backup()
    elif args.command == 'restore':
        restore(args.archive)
    elif args.command == 'provision':
        apply(provision(state, args.count))
    elif args.command == 'render':
        render(state, tls=not args.http_only)
    elif args.command == 'doctor':
        run('systemctl', 'is-active', 'sa-vpn-xray', 'nginx', 'sa-vpn-renew.timer')
        run('nginx', '-t')
        run('/usr/local/lib/sa-vpn/xray', 'run', '-test', '-config', str(XRAY))
        run('openssl', 'x509', '-checkend', '86400', '-noout',
            '-in', '/etc/letsencrypt/live/sa-vpn/fullchain.pem')
        for c in state['clients']:
            run('curl', '-fsS', '--output', '/dev/null', '--resolve',
                f"{state['ip']}:2096:127.0.0.1",
                f"https://{state['ip']}:2096/sub/{c['token']}")
        print('Службы, конфигурации, сертификат и подписки исправны. Внешний путь не проверен.')
    else:
        changed = copy.deepcopy(state)
        if args.command == 'add':
            if any(c['name'] == args.name for c in state['clients']):
                raise ValueError('Пользователь уже существует')
            changed['clients'].append(client(args.name))
        else:
            changed['clients'] = [c for c in state['clients'] if c['name'] != args.name]
            if len(changed['clients']) == len(state['clients']):
                raise ValueError('Пользователь не найден')
        backup()
        apply(changed)
        links(changed)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        sys.exit(1)
