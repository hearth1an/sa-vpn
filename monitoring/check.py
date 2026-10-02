#!/usr/bin/env python3
"""External TCP availability, not a VLESS handshake or proof of RKN blocking."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request

API = 'https://check-host.net'
MARKER = '[SA VPN monitor]'


def request(url, data=None, method=None, token=None):
    headers = {'Accept': 'application/json', 'User-Agent': 'sa-vpn-availability-monitor/1'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
        headers['X-GitHub-Api-Version'] = '2022-11-28'
    if data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=25) as r:
        return json.load(r)


def choose_nodes(nodes):
    chosen = {}
    for group in ('ru', 'outside'):
        asns, countries = set(), set()
        for host, info in sorted(nodes.items()):
            country = info['location'][0]
            if (country == 'ru') != (group == 'ru'):
                continue
            if info['asn'] in asns or (group == 'outside' and country in countries):
                continue
            chosen[host] = info
            asns.add(info['asn']); countries.add(country)
            if len(asns) == 3:
                break
    return chosen


def tcp_status(result):
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):
        return 'unknown'
    value = result[0]
    if 'time' in value and 'error' not in value:
        return 'ok'
    if 'error' in value:
        return 'failed'
    return 'unknown'


def classify(nodes, results):
    counts = {g: {'ok': 0, 'failed': 0, 'unknown': 0} for g in ('ru', 'outside')}
    for host, info in nodes.items():
        group = 'ru' if info['location'][0] == 'ru' else 'outside'
        counts[group][tcp_status(results.get(host))] += 1
    ru, other = counts['ru'], counts['outside']
    if ru['failed'] >= 2 and other['ok'] >= 2:
        status = 'possible_regional_block'
    elif ru['failed'] >= 2 and other['failed'] >= 2:
        status = 'server_unreachable'
    elif ru['ok'] >= 2 and other['ok'] >= 1 and not ru['failed']:
        status = 'healthy'
    elif ru['ok'] and ru['failed']:
        status = 'regional_degradation'
    else:
        status = 'monitor_inconclusive'
    return status, counts


def probe(target):
    addr = ipaddress.ip_address(target['ip'])
    if addr.version != 4 or not addr.is_global:
        raise ValueError('Expected public IPv4')
    port = int(target['port'])
    if not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    nodes = choose_nodes(request(API + '/nodes/hosts')['nodes'])
    if sum(v['location'][0] == 'ru' for v in nodes.values()) < 2:
        raise ValueError('Not enough independent Russian probes')
    query = urllib.parse.urlencode([('host', f'{addr}:{port}')] + [('node', n) for n in nodes])
    started = request(API + '/check-tcp?' + query)
    if started.get('ok') != 1:
        raise ValueError('Check-Host rejected request')
    # Only account for nodes actually used by Check-Host.
    nodes = {n: nodes[n] for n in started['nodes'] if n in nodes}
    results = {}
    for _ in range(8):
        time.sleep(3)
        results = request(API + '/check-result/' + urllib.parse.quote(started['request_id'], safe=''))
        if all(tcp_status(results.get(n)) != 'unknown' for n in nodes):
            break
    status, counts = classify(nodes, results)
    return {'status': status, 'counts': counts, 'report': started['permanent_link'],
            'nodes': nodes, 'results': results}


def issue_sync(target, report):
    token = os.environ['GITHUB_TOKEN']
    repo = os.environ['GITHUB_REPOSITORY']
    api = f'https://api.github.com/repos/{repo}'
    title = f"{MARKER} {target['ip']}:{target['port']}"
    existing = None
    for page in range(1, 11):
        issues = request(api + f'/issues?state=open&per_page=100&page={page}', token=token)
        existing = next((i for i in issues if i.get('title') == title and 'pull_request' not in i), None)
        if existing or len(issues) < 100:
            break
    body = ('Автоматическая внешняя проверка доступности SA VPN.\n\n'
            'Это TCP-проверка: она не доказывает блокировку РКН и не проверяет VLESS-сессию.\n\n'
            f"Проверено: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n"
            '```json\n' + json.dumps(report, ensure_ascii=False, indent=2) + '\n```')
    status = report['status']
    if status == 'healthy':
        if existing:
            request(api + '/issues/' + str(existing['number']),
                    {'body': body, 'state': 'closed'}, 'PATCH', token)
    elif status == 'transient':
        # A single-round fault never closes or replaces a confirmed incident.
        return
    elif existing:
        request(api + '/issues/' + str(existing['number']), {'body': body}, 'PATCH', token)
    else:
        request(api + '/issues', {'title': title, 'body': body}, 'POST', token)


def check(target):
    try:
        first = probe(target)
        if first['status'] == 'healthy':
            return {'status': 'healthy', 'rounds': [first]}
        time.sleep(20)
        second = probe(target)
        if first['status'] == second['status']:
            return {'status': second['status'], 'rounds': [first, second]}
        return {'status': 'transient', 'rounds': [first, second]}
    except Exception as error:
        return {'status': 'monitor_error', 'error': type(error).__name__ + ': ' + str(error)}


def main():
    targets = json.loads((Path(__file__).parent / 'targets.json').read_text())
    reports = []
    for target in targets:
        report = check(target)
        print(json.dumps({'target': target, **report}, ensure_ascii=False))
        reports.append({'target': target, **report})
        if os.getenv('GITHUB_TOKEN') and os.getenv('GITHUB_REPOSITORY'):
            issue_sync(target, report)
    Path('monitor-result.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2))
    with open(os.environ.get('GITHUB_STEP_SUMMARY', os.devnull), 'a') as summary:
        for r in reports:
            summary.write(f"- {r['target']['ip']}: **{r['status']}**\n")


if __name__ == '__main__':
    main()
