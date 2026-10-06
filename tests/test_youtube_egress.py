import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('youtube_egress',
    Path(__file__).resolve().parents[1] / 'tools/prepare_youtube_egress.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def fixture():
    return {
        'inbounds': [{'tag': 'vpn-one', 'protocol': 'vless', 'settings': {'clients': [{'id': 'private-uuid-1'}]}},
                     {'tag': 'vpn-two', 'protocol': 'trojan', 'settings': {'clients': [{'password': 'private-password'}]}},
                     {'tag': tool.TRANSIT_TAG, 'protocol': 'vless'}, {'tag': 'api', 'protocol': 'dokodemo-door'}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
            {'inboundTag': ['api'], 'outboundTag': 'api'},
            {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'block'},
            {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'direct'}]},
        'dns': {'servers': ['localhost']},
    }


def outbound():
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': 'ru-exit.example', 'port': 443,
             'users': [{'id': 'owned-interserver-uuid', 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'tls',
                               'tlsSettings': {'serverName': 'ru-exit.example'}}}


class YoutubeEgressTests(unittest.TestCase):
    def test_all_users_preserved_protection_first_transit_excluded(self):
        source, exit_config = fixture(), outbound()
        before, exit_before = copy.deepcopy(source), copy.deepcopy(exit_config)
        result = tool.prepare_config(source, exit_config)
        self.assertEqual(source, before)
        self.assertEqual(exit_config, exit_before)
        self.assertEqual(result['inbounds'], before['inbounds'])
        self.assertEqual(result['dns'], before['dns'])
        self.assertEqual(result['outbounds'][:-1], before['outbounds'])
        rules = result['routing']['rules']
        self.assertEqual(rules[:2], before['routing']['rules'][:2])
        self.assertEqual(rules[2]['inboundTag'], ['vpn-one', 'vpn-two'])
        self.assertEqual(rules[3:], before['routing']['rules'][2:])
        self.assertIn('domain:googlevideo.com', rules[2]['domain'])
        self.assertNotIn('domain:instagram.com', rules[2]['domain'])

    def test_rejects_existing_exit_missing_tags_and_unsafe_order(self):
        configs = []
        existing = fixture(); existing['outbounds'].append(dict(outbound(), tag=tool.EXIT_TAG)); configs.append(existing)
        missing = fixture(); missing['inbounds'][0].pop('tag'); configs.append(missing)
        duplicate = fixture(); duplicate['inbounds'][1]['tag'] = 'vpn-one'; configs.append(duplicate)
        late_block = fixture(); late_block['routing']['rules'].append({'outboundTag': 'block'}); configs.append(late_block)
        for config in configs:
            with self.subTest(config=config):
                with self.assertRaises(ValueError): tool.prepare_config(config, outbound())

    def test_rejects_unencrypted_unverified_or_chained_exit(self):
        configs = []
        insecure = outbound(); insecure['streamSettings']['tlsSettings']['allowInsecure'] = True; configs.append(insecure)
        clear = outbound(); clear['streamSettings']['security'] = 'none'; configs.append(clear)
        no_sni = outbound(); no_sni['streamSettings']['tlsSettings'] = {}; configs.append(no_sni)
        chain = outbound(); chain['proxySettings'] = {'tag': 'direct'}; configs.append(chain)
        dialer = outbound(); dialer['streamSettings']['sockopt'] = {'dialerProxy': 'direct'}; configs.append(dialer)
        no_address = outbound(); no_address['settings']['vnext'][0]['address'] = ''; configs.append(no_address)
        for config in configs:
            with self.subTest(config=config):
                with self.assertRaises(ValueError): tool.prepare_config(fixture(), config)

    def test_cli_private_new_file_no_overwrite_no_credentials_on_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, remote, output = root/'source.json', root/'exit.json', root/'candidate.json'
            source.write_text(json.dumps(fixture())); remote.write_text(json.dumps(outbound()))
            command = [sys.executable, str(Path(tool.__file__)), '--xray-config', str(source),
                       '--ru-outbound', str(remote), '--output', str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertNotIn('private-uuid', result.stdout)
            before = output.read_bytes()
            repeated = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
