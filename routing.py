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
