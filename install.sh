#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Generated self-contained installer. Sources: install.template.sh + manager.py.
set -Eeuo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
fail() { printf '\nОшибка: %s\n' "$*" >&2; exit 1; }
trap 'printf "\nУстановка остановлена на строке %s. Исправьте причину и запустите повторно.\n" "$LINENO" >&2' ERR

if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'SA VPN: Ubuntu 22.04/24.04, root, публичный IPv4.' \
      'Опционально: SA_VPN_IP=IPv4, SA_VPN_EMAIL=email (уведомления ACME).' \
      'Требуются свободные TCP 80, 443, 2096. Уже установленный VPN не заменяется.'
    exit 0
fi
[[ $# == 0 ]] || fail 'Неизвестный аргумент. Используйте --help.'
[[ $EUID == 0 ]] || fail 'Войдите как root или используйте sudo bash.'
[[ -d /run/systemd/system ]] || fail 'Нужен VPS с systemd, не контейнер.'
source /etc/os-release
[[ $ID == ubuntu && ($VERSION_ID == 22.04 || $VERSION_ID == 24.04) ]] || fail 'Поддерживается Ubuntu 22.04 или 24.04.'
command -v flock >/dev/null || fail 'Не найден flock (пакет util-linux).'
exec 9>/run/sa-vpn-install.lock
flock -n 9 || fail 'Другой установщик уже работает.'

# A successful repeated run only checks and displays existing links.
if [[ -f /etc/sa-vpn/installed ]]; then
    /usr/local/bin/sa-vpn doctor
    /usr/local/bin/sa-vpn links
    exit 0
fi
if ! { : </dev/tty; } 2>/dev/null; then
    fail 'Нужен интерактивный SSH-терминал для выбора количества ключей.'
fi
[[ ! -e /etc/x-ui/x-ui.db && ! -e /usr/local/x-ui && ! -e /etc/xray/config.json ]] || fail 'Обнаружен другой VPN. Используйте новый VPS; существующие настройки не затронуты.'
command -v ss >/dev/null || fail 'Не найден ss (пакет iproute2).'
if [[ ! -f /etc/sa-vpn/state.json ]]; then
    for port in 80 443 2096 10000; do
        [[ -z $(ss -H -ltn "sport = :$port") ]] || fail "Порт $port уже занят. Используйте чистый VPS."
    done
    [[ ! -d /etc/nginx || -z $(find /etc/nginx -type f -name '*.conf' -print -quit) ]] || fail 'Обнаружена конфигурация nginx. Используйте чистый VPS.'
fi
case $(uname -m) in
    x86_64) asset=Xray-linux-64.zip; sha=b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf ;;
    aarch64) asset=Xray-linux-arm64-v8a.zip; sha=13a251379bea366c2cf10363ad71e75734193d401f26f518bf0c25e5c8f8c931 ;;
    *) fail 'Поддерживается amd64 или arm64.' ;;
esac
printf '\nSA VPN: установка зависимостей…\n'
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl unzip nginx python3 python3-venv openssl qrencode

if [[ -f /etc/sa-vpn/state.json ]]; then
    ip=$(python3 -c 'import json; print(json.load(open("/etc/sa-vpn/state.json"))["ip"])')
else
    ip=${SA_VPN_IP:-$(curl -4 -fsS --retry 3 --connect-timeout 10 --max-time 30 https://api.ipify.org)}
fi
python3 - "$ip" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
if ip.version != 4 or not ip.is_global:
    sys.exit('Нужен публичный IPv4. Задайте SA_VPN_IP.')
PY

work=$(mktemp -d /tmp/sa-vpn-install.XXXXXXXX)
trap 'rm -f "$work/xray.zip"; rm -rf -- "$work"' EXIT
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
    "https://github.com/XTLS/Xray-core/releases/download/v26.6.27/$asset" -o "$work/xray.zip"
printf '%s  %s\n' "$sha" "$work/xray.zip" | sha256sum -c -
unzip -q "$work/xray.zip" -d "$work/xray"
install -d -m 755 /usr/local/lib/sa-vpn /var/lib/sa-vpn/acme /var/lib/sa-vpn/sub
install -d -m 750 /etc/sa-vpn
getent group sa-vpn >/dev/null || groupadd --system sa-vpn
id sa-vpn >/dev/null 2>&1 || useradd --system --gid sa-vpn --home-dir /nonexistent --shell /usr/sbin/nologin sa-vpn
chown root:sa-vpn /etc/sa-vpn
install -m 755 "$work/xray/xray" /usr/local/lib/sa-vpn/xray
install -m 644 "$work/xray/geoip.dat" /usr/local/lib/sa-vpn/geoip.dat
install -m 644 "$work/xray/geosite.dat" /usr/local/lib/sa-vpn/geosite.dat

# Certbot webroot IP support needs >=5.4; distro packages may be older.
python3 -m venv /opt/sa-vpn-certbot
/opt/sa-vpn-certbot/bin/pip install --disable-pip-version-check 'certbot==5.4.0'

cat > /usr/local/bin/sa-vpn <<'SA_VPN_PYTHON'
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

HAPP_ROUTING_PROFILE = {
    'Name': 'SA VPN - RU direct',
    'GlobalProxy': 'true',
    'RemoteDNSType': 'DoH',
    'RemoteDNSDomain': 'https://cloudflare-dns.com/dns-query',
    'RemoteDNSIP': '1.1.1.1',
    'DomesticDNSType': 'DoH',
    'DomesticDNSDomain': 'https://common.dot.dns.yandex.net/dns-query',
    'DomesticDNSIP': '77.88.8.8',
    'Geoipurl': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat',
    'Geositeurl': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat',
    'DnsHosts': {
        'cloudflare-dns.com': '1.1.1.1',
        'common.dot.dns.yandex.net': '77.88.8.8',
    },
    'DirectSites': [
        'domain:kontur.ru',
        'domain:e-kontur.ru',
        'domain:testkontur.ru',
        'domain:skbkontur.ru',
        'domain:ozon.com',
        'domain:ozonusercontent.com',
        'domain:ozoncdn.com',
        'domain:wildberries.com',
        'domain:wbstatic.net',
        'domain:anydesk.com',
        'regexp:\\.ru$',
        'regexp:\\.su$',
        'regexp:\\.xn--p1ai$',
    ],
    'DirectIp': ['geoip:ru', 'geoip:private'],
    'ProxySites': [
        'domain:youtube.com',
        'domain:youtu.be',
        'domain:googlevideo.com',
        'domain:ytimg.com',
        'domain:youtubei.googleapis.com',
        'domain:instagram.com',
        'domain:cdninstagram.com',
        'domain:facebook.com',
        'domain:fbcdn.net',
        'domain:whatsapp.com',
        'domain:whatsapp.net',
    ],
    'ProxyIp': [],
    'BlockSites': [],
    'BlockIp': [],
    'DomainStrategy': 'IPIfNonMatch',
    'FakeDNS': 'false',
    'RouteOrder': ['block', 'direct', 'proxy'],
}


def happ_routing_link():
    payload = json.dumps(HAPP_ROUTING_PROFILE, separators=(',', ':'))
    return 'happ://routing/onadd/' + base64.b64encode(payload.encode()).decode()


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
    routing = happ_routing_link()
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
        add_header routing "{routing}" always;
        add_header routing-enable "true" always;
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
SA_VPN_PYTHON
chmod 755 /usr/local/bin/sa-vpn
/usr/local/bin/sa-vpn init "$ip"

# Only the distribution's default site is removed; custom sites were rejected above.
if [[ -L /etc/nginx/sites-enabled/default && $(readlink /etc/nginx/sites-enabled/default) == /etc/nginx/sites-available/default ]]; then
    unlink /etc/nginx/sites-enabled/default
fi
/usr/local/bin/sa-vpn render --http-only
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# Preserve SSH and all existing firewall rules. Do not enable/reset a firewall.
if command -v ufw >/dev/null && ufw status | head -n1 | grep -q 'Status: active'; then
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 2096/tcp
fi
printf '\nВыпускаю TLS-сертификат для %s (порт 80 должен быть доступен извне)…\n' "$ip"
email_flags=(--register-unsafely-without-email)
[[ -z ${SA_VPN_EMAIL:-} ]] || email_flags=(--email "$SA_VPN_EMAIL")
/opt/sa-vpn-certbot/bin/certbot certonly --non-interactive --agree-tos \
    "${email_flags[@]}" --webroot --webroot-path /var/lib/sa-vpn/acme \
    --preferred-profile shortlived --ip-address "$ip" --cert-name sa-vpn --keep-until-expiring

cat > /etc/systemd/system/sa-vpn-xray.service <<'UNIT'
[Unit]
Description=SA VPN Xray
After=network-online.target
Wants=network-online.target
[Service]
User=sa-vpn
Group=sa-vpn
Environment=XRAY_LOCATION_ASSET=/usr/local/lib/sa-vpn
ExecStart=/usr/local/lib/sa-vpn/xray run -config /etc/sa-vpn/xray.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT

install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/sa-vpn-nginx <<'HOOK'
#!/bin/sh
set -eu
nginx -t
systemctl reload nginx
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/sa-vpn-nginx
cat > /etc/systemd/system/sa-vpn-renew.service <<'UNIT'
[Unit]
Description=Renew SA VPN IP certificate
After=network-online.target nginx.service
[Service]
Type=oneshot
ExecStart=/opt/sa-vpn-certbot/bin/certbot renew --quiet --cert-name sa-vpn
UNIT
cat > /etc/systemd/system/sa-vpn-renew.timer <<'UNIT'
[Unit]
Description=Check SA VPN certificate every six hours
[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/sa-vpn-backup.service <<'UNIT'
[Unit]
Description=Backup SA VPN user keys
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sa-vpn backup
UNIT
cat > /etc/systemd/system/sa-vpn-backup.timer <<'UNIT'
[Unit]
Description=Daily SA VPN backup
[Timer]
OnCalendar=daily
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
UNIT

/usr/local/bin/sa-vpn render
/usr/local/lib/sa-vpn/xray run -test -config /etc/sa-vpn/xray.json
nginx -t
systemctl daemon-reload
systemctl enable --now sa-vpn-xray sa-vpn-renew.timer sa-vpn-backup.timer
systemctl reload nginx
/usr/local/bin/sa-vpn doctor

# Full loopback TLS + WS + VLESS + outbound smoke test, not just a listening port.
python3 - "$work/client.json" "$ip" <<'PY'
import json, sys
state = json.load(open('/etc/sa-vpn/state.json'))
config = {
 'log': {'loglevel': 'warning'},
 'inbounds': [{'listen': '127.0.0.1', 'port': 10888, 'protocol': 'socks', 'settings': {'udp': False}}],
 'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': 443,
 'users': [{'id': state['clients'][0]['id'], 'encryption': 'none'}]}]},
 'streamSettings': {'network': 'ws', 'security': 'tls', 'tlsSettings': {'serverName': state['ip']},
 'wsSettings': {'path': state['path'], 'headers': {'Host': state['ip']}}}}]}
with open(sys.argv[1], 'w') as f: json.dump(config, f)
PY
[[ -z $(ss -H -ltn 'sport = :10888') ]] || fail 'Тестовый порт 10888 занят.'
/usr/local/lib/sa-vpn/xray run -config "$work/client.json" >"$work/client.log" 2>&1 &
test_pid=$!
finish_test() { kill "$test_pid" 2>/dev/null || true; wait "$test_pid" 2>/dev/null || true; }
trap 'finish_test; rm -rf -- "$work"' EXIT
test_ok=0
for attempt in 1 2 3 4 5; do
    printf 'Проверка туннеля: попытка %s/5…\n' "$attempt"
    if actual=$(curl -4 -fsS --connect-timeout 5 --max-time 15 --socks5-hostname 127.0.0.1:10888 https://api.ipify.org); then
        [[ $actual == "$ip" ]] || fail 'Выходной IP не совпал с адресом сервера.'
        test_ok=1
        break
    fi
    sleep 1
done
finish_test
trap 'rm -rf -- "$work"' EXIT
[[ $test_ok == 1 ]] || fail 'Проверка через туннель не прошла. Проверьте journalctl -u sa-vpn-xray.'
printf '\nУстановка и проверка туннеля завершены.\n'
while true; do
    printf 'Сколько ключей выдать? Введите число от 1 до 5: ' >/dev/tty
    IFS= read -r key_count </dev/tty || fail 'Не удалось прочитать количество ключей.'
    if [[ $key_count =~ ^[1-5]$ ]]; then
        break
    fi
    printf 'Введите целое число от 1 до 5.\n' >/dev/tty
done
/usr/local/bin/sa-vpn provision "$key_count"
/usr/local/bin/sa-vpn doctor
date -u +%FT%TZ > /etc/sa-vpn/installed
/usr/local/bin/sa-vpn backup
printf '\nVPN установлен. Добавьте URL подписки в Happ.\n'
/usr/local/bin/sa-vpn links
python3 - <<'PY'
import json, subprocess
state = json.load(open('/etc/sa-vpn/state.json'))
for c in state['clients']:
    print('\nQR подписки: ' + c['name'], flush=True)
    subprocess.run(['qrencode', '-t', 'ANSIUTF8', f"https://{state['ip']}:2096/sub/{c['token']}"], check=True)
PY
printf '\nПроверено локально через TLS/VLESS. Доступ из вашей сети проверьте в Happ.\n'
