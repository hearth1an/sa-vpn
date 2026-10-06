#!/usr/bin/env python3
"""Real Xray + nginx + verified TLS test; entirely temporary config/state.

Run after downloading the pinned Xray asset. No production services are touched.
The test removes private-address blocking only to reach its local HTTP fixture.
"""
import base64
import copy
import http.server
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
spec = importlib.util.spec_from_file_location('manager', repo_root / 'manager.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
egress_spec = importlib.util.spec_from_file_location('youtube_egress', repo_root / 'tools/prepare_youtube_egress.py')
egress = importlib.util.module_from_spec(egress_spec); egress_spec.loader.exec_module(egress)
xray = str(Path(sys.argv[1]).resolve())


class Origin(http.server.BaseHTTPRequestHandler):
    body = b'SA-VPN-INTEGRATION-OK'
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(self.body)
    def log_message(self, *args): pass


class RussianExitOrigin(Origin):
    body = b'SA-VPN-RUSSIAN-EXIT-FIXTURE'


def call(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        print(error.output.decode(errors='replace'), file=sys.stderr)
        raise


with tempfile.TemporaryDirectory(prefix='sa-vpn-test-') as tmp:
    root = Path(tmp)
    os.chmod(root, 0o755)
    state = m.initial_state('8.8.4.4', count=2)
    # A loopback-only IP in test certificate; production validates public IPs.
    state['ip'] = '127.0.0.1'
    cert, key = root / 'fullchain.pem', root / 'privkey.pem'
    call('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-keyout', str(key), '-out', str(cert), '-subj', '/CN=127.0.0.1',
         '-addext', 'subjectAltName=IP:127.0.0.1')
    subdir = root / 'sub'; subdir.mkdir(mode=0o755)
    c = state['clients'][0]
    (subdir / c['token']).write_bytes(base64.b64encode(m.uri(state, c).encode()))
    os.chmod(subdir / c['token'], 0o644)
    server_state = dict(state, ip='8.8.4.4')
    server = m.config(server_state)
    server['log'] = {'loglevel': 'debug'}
    server['routing'] = {'rules': []}  # Local fixture only.
    # Xray also blocks private destinations inside freedom by default.
    # Permit exactly this fixture in the test; production retains that protection.
    server['outbounds'][0]['settings'] = {'finalRules': [
        {'action': 'allow', 'ip': ['127.0.0.1/32'], 'port': '19090'}],
        'redirect': '127.0.0.1:19090'}
    # A separate transit inbound must never be sent back to the Russian exit.
    server['inbounds'].append({'listen': '127.0.0.1', 'port': 10001,
        'tag': egress.TRANSIT_TAG, 'protocol': 'vless',
        'settings': {'decryption': 'none', 'clients': [{'id': c['id']}]}})
    ru_outbound = {'protocol': 'vless', 'settings': {'vnext': [{
        'address': '127.0.0.1', 'port': 19443,
        'users': [{'id': c['id'], 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'tls',
            'tlsSettings': {'serverName': '127.0.0.1',
                'certificates': [{'usage': 'verify', 'certificateFile': str(cert)}]}}}
    before_inbounds = copy.deepcopy(server['inbounds'])
    server = egress.prepare_config(server, ru_outbound)
    assert server['inbounds'] == before_inbounds
    russian_exit = {'log': {'loglevel': 'debug'},
        'inbounds': [{'listen': '127.0.0.1', 'port': 19443, 'tag': 'youtube-from-de',
            'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': [{'id': c['id']}]},
            'streamSettings': {'network': 'tcp', 'security': 'tls',
                'tlsSettings': {'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]}}}],
        'outbounds': [{'protocol': 'freedom', 'settings': {'redirect': '127.0.0.1:19091',
            'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32'], 'port': '19091'}]}}]}
    (root / 'russian-exit.json').write_text(json.dumps(russian_exit))
    (root / 'server.json').write_text(json.dumps(server))
    nginx = m.nginx(state).replace('listen 80;', 'listen 127.0.0.1:9080;') \
        .replace('listen 443 ssl;', 'listen 127.0.0.1:9443 ssl;') \
        .replace('listen 2096 ssl;', 'listen 127.0.0.1:9444 ssl;') \
        .replace('/etc/letsencrypt/live/sa-vpn', str(root)) \
        .replace('/var/lib/sa-vpn', str(root)) \
        .replace('/var/log/nginx/sa-vpn-error.log crit', 'stderr info')
    temps = '\n'.join(f'{kind}_temp_path {root}/{kind};' for kind in
                      ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
    nginx = f'pid {root}/nginx.pid;\nerror_log stderr;\nevents {{}}\nhttp {{\naccess_log off;\n{temps}\n{nginx}\n}}\n'
    (root / 'nginx.conf').write_text(nginx)
    call('nginx', '-t', '-c', str(root / 'nginx.conf'), '-p', str(root))
    call(xray, 'run', '-test', '-config', str(root / 'server.json'))
    call(xray, 'run', '-test', '-config', str(root / 'russian-exit.json'))
    client = {'log': {'loglevel': 'debug'},
              'inbounds': [{'listen': '127.0.0.1', 'port': 10888, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
              'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                  'address': '127.0.0.1', 'port': 9443,
                  'users': [{'id': c['id'], 'encryption': 'none'}]}]},
                  'streamSettings': {'network': 'ws', 'security': 'tls',
                                     'tlsSettings': {'serverName': '127.0.0.1',
                                                     'certificates': [{'usage': 'verify', 'certificateFile': str(cert)}]},
                                     'wsSettings': {'path': state['path']}}}]}
    (root / 'client.json').write_text(json.dumps(client))
    second_client = copy.deepcopy(client)
    second_client['inbounds'][0]['port'] = 10889
    second_client['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'] = state['clients'][1]['id']
    (root / 'second-client.json').write_text(json.dumps(second_client))
    transit_client = copy.deepcopy(client)
    transit_client['inbounds'][0]['port'] = 10890
    transit_client['outbounds'] = [{'protocol': 'vless', 'settings': {'vnext': [{
        'address': '127.0.0.1', 'port': 10001, 'users': [{'id': c['id'], 'encryption': 'none'}]}]}}]
    (root / 'transit-client.json').write_text(json.dumps(transit_client))
    origin = http.server.HTTPServer(('127.0.0.1', 19090), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    ru_origin = http.server.HTTPServer(('127.0.0.1', 19091), RussianExitOrigin)
    threading.Thread(target=ru_origin.serve_forever, daemon=True).start()
    procs = []
    try:
        procs.append(subprocess.Popen(['nginx', '-c', str(root / 'nginx.conf'), '-p', str(root), '-g', 'daemon off;']))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'server.json')]))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'client.json')]))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'russian-exit.json')]))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'second-client.json')]))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'transit-client.json')]))
        for attempt in range(10):
            try:
                result = call('curl', '-fsS', '--max-time', '2', '--noproxy', '',
                              '--socks5-hostname', '127.0.0.1:10888', 'http://127.0.0.1:19090/')
                assert result == b'SA-VPN-INTEGRATION-OK', result
                break
            except subprocess.CalledProcessError:
                if attempt == 9: raise
                time.sleep(0.2)
        body = call('curl', '-fsS', '--cacert', str(cert), f"https://127.0.0.1:9444/sub/{c['token']}")
        assert base64.b64decode(body).decode() == m.uri(state, c)
        headers = call('curl', '-fsS', '--cacert', str(cert), '-D', '-', '-o', '/dev/null',
                       f"https://127.0.0.1:9444/sub/{c['token']}").decode()
        routing_header = next(line.split(':', 1)[1].strip() for line in headers.splitlines()
                              if line.lower().startswith('routing:'))
        decoded = json.loads(base64.b64decode(routing_header.removeprefix('happ://routing/onadd/')))
        assert decoded == m.HAPP_ROUTING_PROFILE
        assert decoded['RouteOrder'] == ['block', 'proxy', 'direct']
        assert 'per-app-proxy-mode:' not in headers.lower()
        for path in ['/sub/', '/sub/' + '0' * 48, '/state.json']:
            code = call('curl', '-sS', '--cacert', str(cert), '-o', '/dev/null', '-w', '%{http_code}',
                        'https://127.0.0.1:9444' + path)
            assert code == b'404', (path, code)
        print('PASS: verified TLS -> WebSocket -> VLESS -> HTTP; subscription and 404 checks')
        for socks_port in (10888, 10889):
            for domain in ('youtube.com', 'r1.googlevideo.com'):
                response = call('curl', '-fsS', '--max-time', '5', '--noproxy', '',
                    '--socks5-hostname', f'127.0.0.1:{socks_port}', f'http://{domain}:19090/')
                assert response == RussianExitOrigin.body, (socks_port, domain, response)
            response = call('curl', '-fsS', '--max-time', '5', '--noproxy', '',
                '--socks5-hostname', f'127.0.0.1:{socks_port}', 'http://instagram.com:19090/')
            assert response == Origin.body, response
        response = call('curl', '-fsS', '--max-time', '5', '--noproxy', '',
            '--socks5-hostname', '127.0.0.1:10890', 'http://youtube.com:19090/')
        assert response == Origin.body, response
        print('PASS: two existing users -> verified TLS exit for YouTube; other domains and transit stay on DE fixture')
    finally:
        origin.shutdown()
        ru_origin.shutdown()
        for proc in reversed(procs): proc.terminate()
        for proc in reversed(procs):
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
