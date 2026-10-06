#!/usr/bin/env python3
"""Compare a VPS IP with community observations; never probe or change a server."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import urllib.request

UPSTREAM = 'hxehex/russia-mobile-internet-whitelist'
DEFAULT_REF = 'fad3653ebd4b212643774a4d10af3eb33838e4ff'
UPSTREAM_FILE = 'cidrwhitelist.txt'
MAX_BYTES = 2 * 1024 * 1024


def parse_networks(data):
    if len(data) > MAX_BYTES:
        raise ValueError('Список больше допустимого размера.')
    networks = set()
    for number, line in enumerate(data.decode('utf-8-sig').splitlines(), 1):
        entry = line.split('#', 1)[0].strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError:
            raise ValueError(f'Некорректный IP/CIDR в строке {number}.') from None
        if network.prefixlen == 0:
            raise ValueError(f'Маршрут по умолчанию в строке {number}: такой список непригоден.')
        networks.add(network)
    if not networks:
        raise ValueError('Пустой список: вывод о наличии IP делать нельзя.')
    return sorted(networks, key=lambda network: (network.version, int(network.network_address), network.prefixlen))


def inspect(ip, data, source):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        raise ValueError('Укажите публичный IP своего VPS.')
    networks = parse_networks(data)
    matches = [str(network) for network in networks
               if network.version == address.version and address in network]
    return {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'server_ip': str(address),
        'observation': 'listed_in_community_cidrs' if matches else 'not_listed_in_community_cidrs',
        'matching_cidrs': matches,
        'source': {**source, 'sha256': hashlib.sha256(data).hexdigest(), 'network_count': len(networks)},
        'operator_reachability': 'not_tested',
        'vless_session': 'not_tested',
        'routing_changed': False,
        'note': ('Это сопоставление с неофициальным списком наблюдений, а не проверка сети. '
                 'Наличие или отсутствие IP в нём не доказывает доступность, блокировку РКН '
                 'или работу VLESS. Проверять вход нужно с нужной SIM во время ограничений.'),
    }


def fetch(ref, timeout):
    if not re.fullmatch(r'[0-9a-f]{40}', ref):
        raise ValueError('Версия источника должна быть полным SHA коммита (40 символов).')
    url = f'https://raw.githubusercontent.com/{UPSTREAM}/{ref}/{UPSTREAM_FILE}'
    # Fixed upstream and path: external data never supplies URLs or commands.
    request = urllib.request.Request(url, headers={'User-Agent': 'sa-vpn-whitelist-audit/1'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.geturl() != url:
            raise ValueError('Источник неожиданно перенаправил запрос.')
        data = response.read(MAX_BYTES + 1)
    return data, {'repository': UPSTREAM, 'ref': ref, 'path': UPSTREAM_FILE, 'url': url}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-ip', required=True, help='Public IP of your own VPS; no connections to it')
    parser.add_argument('--list', type=Path, help='Previously downloaded CIDR/IP text file for offline analysis')
    parser.add_argument('--ref', default=DEFAULT_REF, help='Pinned community commit, not a mutable latest list')
    parser.add_argument('--timeout', type=float, default=15, help='Download timeout, seconds (1–60)')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        parser.error('--timeout должен быть от 1 до 60 секунд.')
    try:
        address = ipaddress.ip_address(args.server_ip)
        if not address.is_global:
            raise ValueError('Укажите публичный IP своего VPS.')
        if args.list:
            # Bound reads just like downloads; oversized input is inconclusive.
            with args.list.open('rb') as file:
                data = file.read(MAX_BYTES + 1)
            source = {'local_file': args.list.name}
        else:
            data, source = fetch(args.ref, args.timeout)
        report = inspect(str(address), data, source)
    except (ValueError, OSError, UnicodeError) as error:
        # No partially parsed list, no fallback to a stale or different source.
        report = {'observation': 'monitor_inconclusive', 'error': str(error),
                  'operator_reachability': 'not_tested', 'vless_session': 'not_tested',
                  'routing_changed': False}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
