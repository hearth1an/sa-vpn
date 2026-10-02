#!/usr/bin/env python3
"""Real Xray + nginx + verified TLS test; entirely temporary config/state.

Run after downloading the pinned Xray asset. No production services are touched.
The test removes private-address blocking only to reach its local HTTP fixture.
"""
import base64
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

spec = importlib.util.spec_from_file_location('manager', Path(__file__).resolve().parents[1] / 'manager.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
xray = str(Path(sys.argv[1]).resolve())


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'SA-VPN-INTEGRATION-OK')
    def log_message(self, *args): pass


def call(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        print(error.output.decode(errors='replace'), file=sys.stderr)
        raise


with tempfile.TemporaryDirectory(prefix='sa-vpn-test-') as tmp:
    root = Path(tmp)
    os.chmod(root, 0o755)
    state = m.initial_state('8.8.4.4')
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
    server['routing'] = {'rules': []}  # Local fixture only.
    (root / 'server.json').write_text(json.dumps(server))
    nginx = m.nginx(state).replace('listen 80;', 'listen 127.0.0.1:9080;') \
        .replace('listen 443 ssl;', 'listen 127.0.0.1:9443 ssl;') \
        .replace('listen 2096 ssl;', 'listen 127.0.0.1:9444 ssl;') \
        .replace('/etc/letsencrypt/live/sa-vpn', str(root)) \
        .replace('/var/lib/sa-vpn', str(root)) \
        .replace('/var/log/nginx/sa-vpn-error.log', str(root / 'nginx-error.log'))
    temps = '\n'.join(f'{kind}_temp_path {root}/{kind};' for kind in
                      ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
    nginx = f'pid {root}/nginx.pid;\nerror_log stderr;\nevents {{}}\nhttp {{\naccess_log off;\n{temps}\n{nginx}\n}}\n'
    (root / 'nginx.conf').write_text(nginx)
    call('nginx', '-t', '-c', str(root / 'nginx.conf'), '-p', str(root))
    call(xray, 'run', '-test', '-config', str(root / 'server.json'))
    client = {'inbounds': [{'listen': '127.0.0.1', 'port': 10888, 'protocol': 'socks'}],
              'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                  'address': '127.0.0.1', 'port': 9443,
                  'users': [{'id': c['id'], 'encryption': 'none'}]}]},
                  'streamSettings': {'network': 'ws', 'security': 'tls',
                                     'tlsSettings': {'serverName': '127.0.0.1',
                                                     'certificates': [{'usage': 'verify', 'certificateFile': str(cert)}]},
                                     'wsSettings': {'path': state['path']}}}]}
    (root / 'client.json').write_text(json.dumps(client))
    origin = http.server.HTTPServer(('127.0.0.1', 19090), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    procs = []
    try:
        procs.append(subprocess.Popen(['nginx', '-c', str(root / 'nginx.conf'), '-p', str(root), '-g', 'daemon off;']))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'server.json')]))
        procs.append(subprocess.Popen([xray, 'run', '-config', str(root / 'client.json')]))
        for attempt in range(30):
            try:
                result = call('curl', '-fsS', '--max-time', '3', '--noproxy', '',
                              '--socks5-hostname', '127.0.0.1:10888', 'http://127.0.0.1:19090/')
                assert result == b'SA-VPN-INTEGRATION-OK', result
                break
            except subprocess.CalledProcessError:
                if attempt == 29: raise
                time.sleep(0.2)
        body = call('curl', '-fsS', '--cacert', str(cert), f"https://127.0.0.1:9444/sub/{c['token']}")
        assert base64.b64decode(body).decode() == m.uri(state, c)
        for path in ['/sub/', '/sub/' + '0' * 48, '/state.json']:
            code = call('curl', '-sS', '--cacert', str(cert), '-o', '/dev/null', '-w', '%{http_code}',
                        'https://127.0.0.1:9444' + path)
            assert code == b'404', (path, code)
        print('PASS: verified TLS -> WebSocket -> VLESS -> HTTP; subscription and 404 checks')
    finally:
        origin.shutdown()
        for proc in reversed(procs): proc.terminate()
        for proc in reversed(procs):
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
