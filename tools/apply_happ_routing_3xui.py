#!/usr/bin/env python3
"""Apply the SA VPN Happ routing profile to an existing 3x-ui installation."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time


PROFILE = {
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

DB = Path('/etc/x-ui/x-ui.db')
RUNTIME = Path('/usr/local/x-ui/bin/config.json')
SETTINGS = ('subEnableRouting', 'subRoutingRules')


def routing_link():
    payload = json.dumps(PROFILE, separators=(',', ':'))
    return 'happ://routing/onadd/' + base64.b64encode(payload.encode()).decode()


def set_value(db, key, value):
    if not db.execute('update settings set value=? where key=?', (value, key)).rowcount:
        db.execute('insert into settings(key,value) values(?,?)', (key, value))


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root или через sudo.')
    if not DB.is_file() or not RUNTIME.is_file():
        raise SystemExit('Не найдена действующая установка 3x-ui.')

    db = sqlite3.connect(DB)
    backup = DB.with_name(f'{DB.name}.before-routing-{int(time.time())}.bak')
    destination = sqlite3.connect(backup)
    db.backup(destination)
    destination.close()
    old = {key: db.execute('select value from settings where key=?', (key,)).fetchone()
           for key in SETTINGS}
    before_inbounds = json.loads(RUNTIME.read_text())['inbounds']

    try:
        set_value(db, 'subEnableRouting', 'true')
        set_value(db, 'subRoutingRules', routing_link())
        db.commit()
        subprocess.run(['systemctl', 'restart', 'x-ui'], check=True)
        time.sleep(2)
        subprocess.run(['systemctl', 'is-active', '--quiet', 'x-ui'], check=True)
        after_inbounds = json.loads(RUNTIME.read_text())['inbounds']
        if after_inbounds != before_inbounds:
            raise RuntimeError('3x-ui изменил VPN-входы при обновлении маршрутизации')
        enabled = db.execute(
            'select value from settings where key=?', ('subEnableRouting',)).fetchone()
        rules = db.execute(
            'select value from settings where key=?', ('subRoutingRules',)).fetchone()
        if enabled != ('true',) or rules != (routing_link(),):
            raise RuntimeError('3x-ui не сохранил профиль маршрутизации')
    except Exception:
        for key, value in old.items():
            if value is None:
                db.execute('delete from settings where key=?', (key,))
            else:
                set_value(db, key, value[0])
        db.commit()
        subprocess.run(['systemctl', 'restart', 'x-ui'], check=False)
        raise
    finally:
        db.close()

    print('Маршрутизация Happ обновлена; VPN-входы и пользовательские ключи сохранены.')
    print(f'Резервная копия: {backup}')


if __name__ == '__main__':
    main()
