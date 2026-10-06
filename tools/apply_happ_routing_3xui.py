#!/usr/bin/env python3
"""Source template. build.py produces the self-contained 3x-ui update script."""
import argparse
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

"""Canonical, credential-free client routing. Embedded by build.py for deployment.

Happ's routing profile is not an app/process exclusion and is not a server
outbound configuration. Experimental geodata must be selected explicitly.
"""
import base64
import copy
import json

PROFILE_NAMES = ('baseline', 'runetfreedom', 'youtube-direct-test')
ANYDESK_ANDROID_PACKAGE = 'com.anydesk.anydeskandroid'
YOUTUBE_DOMAINS = (
    'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com',
    'youtubei.googleapis.com',
)

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
        'domain:kontur.ru', 'domain:e-kontur.ru', 'domain:testkontur.ru',
        'domain:skbkontur.ru', 'domain:ozon.com', 'domain:ozonusercontent.com',
        'domain:ozoncdn.com', 'domain:wildberries.com', 'domain:wbstatic.net',
        # Includes *.net.anydesk.com; does not cover arbitrary peer IPs.
        'domain:anydesk.com',
        r'regexp:\.ru$', r'regexp:\.su$', r'regexp:\.xn--p1ai$',
    ],
    'DirectIp': ['geoip:ru', 'geoip:private'],
    'ProxySites': [
        'domain:youtube.com', 'domain:youtu.be', 'domain:googlevideo.com',
        'domain:ytimg.com', 'domain:youtubei.googleapis.com',
        'domain:instagram.com', 'domain:cdninstagram.com',
        'domain:ig.me', 'domain:igcdn.com', 'domain:igsonar.com',
        'domain:facebook.com', 'domain:fbcdn.net',
        'domain:whatsapp.com', 'domain:whatsapp.net',
    ],
    'ProxyIp': [],
    'BlockSites': [],
    'BlockIp': [],
    'DomainStrategy': 'IPIfNonMatch',
    'FakeDNS': 'false',
    # Explicit service domains win over broad RU direct classification.
    'RouteOrder': ['block', 'proxy', 'direct'],
}


def build_happ_profile(name='baseline'):
    if name not in PROFILE_NAMES:
        raise ValueError('Unknown routing profile: ' + str(name))
    profile = copy.deepcopy(HAPP_ROUTING_PROFILE)
    if name == 'runetfreedom':
        # Separate name: importing this never overwrites the baseline profile.
        profile['Name'] = 'SA VPN - RU direct - experimental geodata'
        base = 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/'
        profile['Geoipurl'] = base + 'geoip.dat'
        profile['Geositeurl'] = base + 'geosite.dat'
        profile['ProxySites'] += ['geosite:meta', 'geosite:youtube']
        profile['DirectSites'] += ['geosite:ru-available-only-inside']
        # Do not turn ru-whitelist into broad direct routes or activate
        # ru-blocked-all (700k+ entries) on memory-limited mobile clients.
        # ru-blocked is also not automatic: grouped proxy rules can override
        # explicit direct exceptions when a community list includes them.
    elif name == 'youtube-direct-test':
        # Control experiment: exit via the user's ISP, not an ad blocker.
        # Remove explicit proxy rules first: proxy precedes direct in Happ.
        profile['Name'] = 'SA VPN - YouTube direct test'
        rules = ['domain:' + domain for domain in YOUTUBE_DOMAINS]
        profile['ProxySites'] = [rule for rule in profile['ProxySites'] if rule not in rules]
        profile['DirectSites'] += rules + [
            'domain:youtube.googleapis.com', 'domain:youtube-nocookie.com', 'domain:yt.be',
        ]
    return profile


def happ_routing_link(profile=None, activate=True):
    profile = build_happ_profile() if profile is None else profile
    payload = json.dumps(profile, separators=(',', ':'), ensure_ascii=True)
    action = 'onadd' if activate else 'add'
    return 'happ://routing/' + action + '/' + base64.b64encode(payload.encode()).decode()


def anydesk_singbox_rule():
    """A rule fragment, not a complete TUN config. Put before broad proxy rules.

    The client must support process lookup and already define outbound 'direct'.
    Custom AnyDesk executables/services need their observed names added locally.
    """
    return {'process_name': ['AnyDesk.exe', 'AnyDesk', 'anydesk'],
            'action': 'route', 'outbound': 'direct'}


def anydesk_android_headers(provider_id):
    """Opt-in Happ extended headers; never emitted for ordinary subscriptions."""
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise ValueError('Happ Provider ID is required; use manual app exclusion otherwise')
    if any(c in provider_id for c in '\r\n'):
        raise ValueError('Invalid Provider ID')
    # Explicit opt-in only: Provider ID enables Happ device telemetry. Never
    # add these headers to ordinary subscriptions or replace app lists silently.
    return {'providerid': provider_id.strip(), 'per-app-proxy-mode': 'bypass',
            'per-app-proxy-list': ANYDESK_ANDROID_PACKAGE}

PROFILE = HAPP_ROUTING_PROFILE
DB = Path('/etc/x-ui/x-ui.db')
RUNTIME = Path('/usr/local/x-ui/bin/config.json')
SETTINGS = ('subEnableRouting', 'subRoutingRules')


def routing_link(profile=None):
    return happ_routing_link(PROFILE if profile is None else profile)


def set_value(db, key, value):
    if not db.execute('update settings set value=? where key=?', (value, key)).rowcount:
        db.execute('insert into settings(key,value) values(?,?)', (key, value))


def apply_profile(profile, db_path, runtime_path):
    """Only mutate two subscription settings, with private backup and rollback."""
    db_path, runtime_path = Path(db_path), Path(runtime_path)
    if not db_path.is_file() or not runtime_path.is_file():
        raise ValueError('Не найдена действующая установка 3x-ui.')
    before_inbounds = json.loads(runtime_path.read_text())['inbounds']
    link = routing_link(profile)
    db = sqlite3.connect(db_path)
    try:
        # Check the expected schema before creating a backup or changing settings.
        before_rows = db.execute('select * from inbounds order by id').fetchall()
        old = {key: db.execute('select value from settings where key=?', (key,)).fetchone()
               for key in SETTINGS}
        backup = db_path.with_name(f'{db_path.name}.before-routing-{time.time_ns()}.bak')
        # Create exclusively with private permissions before SQLite writes keys.
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(backup)) as destination:
            db.backup(destination)

        try:
            set_value(db, 'subEnableRouting', 'true')
            set_value(db, 'subRoutingRules', link)
            db.commit()
            subprocess.run(['systemctl', 'restart', 'x-ui'], check=True)
            time.sleep(2)
            subprocess.run(['systemctl', 'is-active', '--quiet', 'x-ui'], check=True)
            if json.loads(runtime_path.read_text())['inbounds'] != before_inbounds:
                raise RuntimeError('3x-ui изменил VPN-входы при обновлении маршрутизации')
            if db.execute('select * from inbounds order by id').fetchall() != before_rows:
                raise RuntimeError('Изменились строки VPN-входов/пользователей в базе')
            actual = {key: db.execute('select value from settings where key=?', (key,)).fetchone()
                      for key in SETTINGS}
            if actual != {'subEnableRouting': ('true',), 'subRoutingRules': (link,)}:
                raise RuntimeError('3x-ui не сохранил профиль маршрутизации')
        except Exception:
            db.rollback()
            for key, value in old.items():
                if value is None:
                    db.execute('delete from settings where key=?', (key,))
                else:
                    set_value(db, key, value[0])
            db.commit()
            subprocess.run(['systemctl', 'restart', 'x-ui'], check=False)
            raise
        return backup
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description='Обновление маршрутизации Happ в 3x-ui')
    parser.add_argument('--profile', choices=PROFILE_NAMES, default='baseline')
    parser.add_argument('--dry-run', action='store_true', help='Показать профиль, ничего не менять')
    args = parser.parse_args()
    profile = build_happ_profile(args.profile)
    if args.dry_run:
        print(json.dumps(profile, ensure_ascii=False, indent=2))
        return
    if os.geteuid() != 0:
        parser.error('Запустите от root или через sudo.')
    backup = apply_profile(profile, DB, RUNTIME)
    print('Маршрутизация Happ обновлена; VPN-входы и пользовательские ключи сохранены.')
    print(f'Резервная копия: {backup}')
    print('Обновите подписку в Happ, дождитесь загрузки геофайлов и переподключитесь.')
    print('Перезапуск 3x-ui может кратковременно прервать активные подключения.')


if __name__ == '__main__':
    main()
