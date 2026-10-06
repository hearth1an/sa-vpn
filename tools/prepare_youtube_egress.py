#!/usr/bin/env python3
"""Prepare a private Xray candidate for all existing VLESS/Trojan users.

Does not edit 3x-ui, subscriptions or services. A real, separately configured
Russian exit is required; configuration alone proves neither country nor access.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import sys

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

EXIT_TAG = 'sa-vpn-youtube-ru'
TRANSIT_TAG = 'sa-vpn-ru-transit'
MAX_BYTES = 2 * 1024 * 1024


def validate_exit(outbound):
    if not isinstance(outbound, dict) or outbound.get('protocol') not in ('vless', 'trojan'):
        raise ValueError('Нужен реальный VLESS/Trojan outbound российского выхода.')
    stream = outbound.get('streamSettings', {})
    if stream.get('security') not in ('tls', 'reality'):
        raise ValueError('Межсерверный выход требует TLS или REALITY.')
    security = stream.get(stream['security'] + 'Settings', {})
    if not security.get('serverName') or security.get('allowInsecure', False) is not False:
        raise ValueError('Укажите SNI; проверка сервера должна оставаться включённой.')
    if outbound.get('proxySettings') or stream.get('sockopt', {}).get('dialerProxy'):
        raise ValueError('Выход не должен ссылаться на другую цепочку proxy.')
    settings = outbound.get('settings', {})
    servers = settings.get('vnext', []) if outbound['protocol'] == 'vless' else settings.get('servers', [])
    # Also accept the current flat VLESS settings format.
    if not servers and outbound['protocol'] == 'vless' and settings.get('address'):
        servers = [settings]
    if len(servers) != 1 or not isinstance(servers[0], dict):
        raise ValueError('Укажите ровно один адрес реального выхода.')
    endpoint = servers[0]
    if not isinstance(endpoint.get('address'), str) or not endpoint['address'].strip():
        raise ValueError('Не указан адрес выхода.')
    port = endpoint.get('port')
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Некорректный порт выхода.')


def prepare_config(source, outbound, exclude_tags=()):
    validate_exit(outbound)
    candidate = copy.deepcopy(source)
    inbounds, outbounds = candidate.get('inbounds'), candidate.get('outbounds')
    if not isinstance(inbounds, list) or not isinstance(outbounds, list) or not outbounds:
        raise ValueError('Нужен полный действующий runtime Xray с inbounds и outbounds.')
    excluded = set(exclude_tags) | {TRANSIT_TAG}
    tags = []
    for inbound in inbounds:
        if inbound.get('protocol') in ('vless', 'trojan') and inbound.get('tag') not in excluded:
            if not isinstance(inbound.get('tag'), str) or not inbound['tag']:
                raise ValueError('Каждый клиентский вход должен иметь непустой tag.')
            tags.append(inbound['tag'])
    if not tags or len(tags) != len(set(tags)):
        raise ValueError('Не найдены однозначные клиентские входы.')
    if EXIT_TAG in [item.get('tag') for item in outbounds]:
        raise ValueError('Такой выход уже настроен; проверьте существующую конфигурацию.')
    routing = candidate.setdefault('routing', {})
    rules = routing.setdefault('rules', [])
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise ValueError('Некорректные правила маршрутизации.')
    blocked = {item['tag'] for item in outbounds
               if item.get('protocol') == 'blackhole' and isinstance(item.get('tag'), str)}
    def protected(rule):
        return rule.get('outboundTag') in blocked or rule.get('outboundTag') == 'api'
    position = 0
    while position < len(rules) and protected(rules[position]):
        position += 1
    if any(protected(rule) for rule in rules[position:]):
        raise ValueError('Защитные/API-правила должны предшествовать обычным маршрутам; нужен разбор порядка.')
    domains = list(YOUTUBE_DOMAINS) + ['youtube.googleapis.com', 'youtube-nocookie.com', 'yt.be']
    rules.insert(position, {'type': 'field', 'inboundTag': tags,
                            'domain': ['domain:' + domain for domain in domains],
                            'outboundTag': EXIT_TAG})
    exit_outbound = copy.deepcopy(outbound)
    exit_outbound['tag'] = EXIT_TAG
    outbounds.append(exit_outbound)
    return candidate


def read_json(path):
    with Path(path).open('rb') as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Конфигурация больше допустимого размера.')
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError('Конфигурация должна быть JSON-объектом.')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xray-config', type=Path, required=True)
    parser.add_argument('--ru-outbound', type=Path, required=True, help='Private JSON of an existing, authorized exit')
    parser.add_argument('--exclude-inbound', action='append', default=[], help='Additional server-to-server inbound tag')
    parser.add_argument('--output', type=Path, required=True, help='New private candidate file; never overwrite runtime')
    args = parser.parse_args()
    try:
        source = read_json(args.xray_config)
        candidate = prepare_config(source, read_json(args.ru_outbound), args.exclude_inbound)
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as target:
            json.dump(candidate, target, indent=2)
            target.write('\n')
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        parser.exit(2, 'Не удалось подготовить конфигурацию; проверьте входные файлы и новый путь вывода.\n')
    print('Подготовлен закрытый кандидат Xray; сервер и подписки не изменены.')
    print('UUID, клиентские входы и прежний выход по умолчанию сохранены.')
    print('Перед применением: Xray -test, проверка российского IP и реальных запросов.')
    print('Доменные правила требуют домена в запросе или настроенного sniffing; рекламы и обхода не гарантируют.')
    print('В 3x-ui изменения outbounds/routing нужно сохранять через её настройки; runtime перегенерируется.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
