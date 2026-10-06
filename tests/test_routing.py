import base64
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import routing
import manager

ROOT = Path(__file__).resolve().parents[1]


def reference_route(profile, domain='', known_ip_groups=(), geosites=None):
    """Reference check for known metadata, NOT a Happ/geodata integration test.

    known_ip_groups represent IP metadata already known on TUN/sniffed requests;
    this does not pretend to perform Xray's IPIfNonMatch DNS resolution.
    """
    domain = domain.rstrip('.').lower()
    geosites = geosites or {}
    for route in profile['RouteOrder']:
        field = route.title()
        for rule in profile[field + 'Sites']:
            kind, value = rule.split(':', 1)
            if kind == 'domain':
                matched = domain == value or domain.endswith('.' + value)
            elif kind == 'regexp':
                matched = re.search(value, domain) is not None
            elif kind == 'geosite':
                matched = domain in geosites.get(value, set())
            else:
                raise AssertionError('Unsupported fixture rule: ' + rule)
            if matched:
                return route
        if any(rule in known_ip_groups for rule in profile[field + 'Ip']):
            return route
    return 'proxy' if profile['GlobalProxy'] == 'true' else 'direct'


class RoutingTests(unittest.TestCase):
    def test_direct_exceptions_and_subdomain_boundaries(self):
        profile = routing.build_happ_profile()
        for domain in ('elba.kontur.ru', 'login.kontur.ru', 'api.e-kontur.ru',
                       'ozon.com', 'img.ozonusercontent.com', 'wildberries.ru',
                       'anydesk.com', 'relay.net.anydesk.com', 'service.su', 'site.xn--p1ai'):
            with self.subTest(domain=domain):
                self.assertEqual(reference_route(profile, domain), 'direct')
        for domain in ('notanydesk.com', 'anydesk.com.evil.example',
                       'kontur.ru.evil.example', 'example.ru.com'):
            self.assertEqual(reference_route(profile, domain), 'proxy')

    def test_explicit_proxy_wins_over_known_ru_ip(self):
        profile = routing.build_happ_profile()
        for domain in ('www.instagram.com', 'video.cdninstagram.com', 'ig.me',
                       'static.igcdn.com', 'www.facebook.com', 'video.fbcdn.net',
                       'youtube.com', 'r1.googlevideo.com', 'ytimg.com', 'whatsapp.net'):
            with self.subTest(domain=domain):
                self.assertEqual(reference_route(profile, domain, ('geoip:ru',)), 'proxy')
        self.assertEqual(reference_route(profile, 'unknown.example', ('geoip:ru',)), 'direct')
        self.assertEqual(reference_route(profile, known_ip_groups=('geoip:private',)), 'direct')
        self.assertEqual(reference_route(profile, 'unknown.example'), 'proxy')

    def test_block_order_and_no_false_youtube_adblocking(self):
        profile = routing.build_happ_profile()
        self.assertEqual(profile['RouteOrder'], ['block', 'proxy', 'direct'])
        self.assertEqual(profile['BlockSites'], [])
        self.assertEqual(profile['BlockIp'], [])
        profile['BlockSites'] = ['domain:instagram.com']
        self.assertEqual(reference_route(profile, 'instagram.com', ('geoip:ru',)), 'block')

    def test_profiles_are_isolated_and_experiments_opt_in(self):
        before = copy.deepcopy(routing.HAPP_ROUTING_PROFILE)
        experiment = routing.build_happ_profile('runetfreedom')
        self.assertNotEqual(experiment['Name'], before['Name'])
        self.assertIn('runetfreedom', experiment['Geositeurl'])
        self.assertIn('geosite:meta', experiment['ProxySites'])
        self.assertEqual(reference_route(experiment, 'fixture.ru', geosites={'meta': {'fixture.ru'}}), 'proxy')
        all_rules = sum((v for k, v in experiment.items() if k.endswith(('Sites', 'Ip'))), [])
        self.assertNotIn('geoip:ru-whitelist', all_rules)
        self.assertNotIn('geosite:ru-blocked-all', all_rules)
        experiment['DirectSites'].clear()
        self.assertEqual(routing.HAPP_ROUTING_PROFILE, before)
        self.assertEqual(routing.build_happ_profile(), before)
        with self.assertRaises(ValueError):
            routing.build_happ_profile('unknown')

    def test_link_roundtrip_and_nonactivating_export(self):
        for name in routing.PROFILE_NAMES:
            profile = routing.build_happ_profile(name)
            for active in (True, False):
                link = routing.happ_routing_link(profile, activate=active)
                self.assertIn('/onadd/' if active else '/add/', link)
                self.assertEqual(json.loads(base64.b64decode(link.rsplit('/', 1)[1])), profile)
        output = subprocess.check_output([sys.executable, str(ROOT / 'tools/export_client_profiles.py'),
                                          '--profile', 'runetfreedom', '--format', 'happ-link'], text=True)
        self.assertTrue(output.startswith('happ://routing/add/'))

    def test_process_fragment_is_not_in_ordinary_happ_profile(self):
        rule = routing.anydesk_singbox_rule()
        self.assertEqual(rule['action'], 'route')
        self.assertEqual(rule['outbound'], 'direct')
        self.assertIn('AnyDesk.exe', rule['process_name'])
        self.assertNotIn('process_name', routing.build_happ_profile())
        for invalid in (None, '', ' ', 'id\r\nInjected: true'):
            with self.assertRaises(ValueError):
                routing.anydesk_android_headers(invalid)
        headers = routing.anydesk_android_headers('registered-provider')
        self.assertEqual(headers['providerid'], 'registered-provider')
        self.assertEqual(headers['per-app-proxy-mode'], 'bypass')
        self.assertEqual(headers['per-app-proxy-list'], 'com.anydesk.anydeskandroid')
        self.assertNotIn('per-app-proxy-list-set', headers)
        self.assertNotIn('per-app-proxy-mode', manager.nginx(manager.initial_state('8.8.4.4')))

    def test_deployment_scripts_are_self_contained(self):
        source = subprocess.check_output([sys.executable, str(ROOT / 'build.py'), '--manager'], text=True)
        installer = (ROOT / 'install.sh').read_text()
        embedded = installer.split("<<'SA_VPN_PYTHON'\n", 1)[1].split('\nSA_VPN_PYTHON', 1)[0]
        self.assertEqual(source.rstrip(), embedded)
        with tempfile.TemporaryDirectory() as temp:
            manager_file = Path(temp) / 'manager.py'
            manager_file.write_text(source)
            output = subprocess.check_output([sys.executable, '-I', str(manager_file),
                                               'routing', '--dry-run'], cwd=temp, text=True)
            self.assertEqual(output.strip(), routing.happ_routing_link())
            tool_source = (ROOT / 'tools/apply_happ_routing_3xui.py').read_text()
            tool_file = Path(temp) / 'apply.py'
            tool_file.write_text(tool_source)
            output = subprocess.check_output([sys.executable, '-I', str(tool_file), '--dry-run'],
                                              cwd=temp, text=True)
            self.assertEqual(json.loads(output), routing.build_happ_profile())

    def test_selected_profile_survives_other_manager_operations(self):
        state = manager.initial_state('8.8.4.4')
        state['routing_profile'] = 'runetfreedom'
        manager.validate(state)
        self.assertIn(routing.happ_routing_link(routing.build_happ_profile('runetfreedom')),
                      manager.nginx(state))
        state['routing_profile'] = 'invalid'
        with self.assertRaises(ValueError):
            manager.validate(state)

    def test_routing_update_does_not_touch_xray_or_credentials(self):
        state = manager.initial_state('8.8.4.4')
        original_state = copy.deepcopy(state)
        original_nginx = manager.nginx(state) + '\n# preserved local customization\n'
        with patch.object(Path, 'read_text', return_value=original_nginx), \
             patch.object(manager, 'atomic') as atomic, patch.object(manager, 'backup'), \
             patch.object(manager, 'run') as run:
            manager.apply_routing(state, 'runetfreedom')
        saved = json.loads(atomic.call_args_list[-1].args[1])
        self.assertEqual(saved['clients'], state['clients'])
        self.assertEqual(saved['path'], state['path'])
        self.assertEqual(state, original_state)
        self.assertIn('# preserved local customization', atomic.call_args_list[0].args[1])
        self.assertEqual([c.args for c in run.call_args_list],
                         [('nginx', '-t'), ('systemctl', 'reload', 'nginx')])

    def test_routing_failure_restores_header_and_does_not_save_state(self):
        state = manager.initial_state('8.8.4.4')
        previous = manager.nginx(state)
        with patch.object(Path, 'read_text', return_value=previous), \
             patch.object(manager, 'atomic') as atomic, patch.object(manager, 'backup'), \
             patch.object(manager, 'run', side_effect=[RuntimeError('nginx check failed'), None, None]):
            with self.assertRaises(RuntimeError):
                manager.apply_routing(state, 'baseline')
        self.assertEqual(len(atomic.call_args_list), 2)
        self.assertEqual(atomic.call_args_list[-1].args[1], previous)

    def test_ambiguous_nginx_is_not_changed(self):
        state = manager.initial_state('8.8.4.4')
        for text in ('no header', manager.nginx(state) * 2):
            with patch.object(Path, 'read_text', return_value=text), \
                 patch.object(manager, 'atomic') as atomic, patch.object(manager, 'backup') as backup:
                with self.assertRaises(ValueError):
                    manager.apply_routing(state, 'baseline')
                atomic.assert_not_called()
                backup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
