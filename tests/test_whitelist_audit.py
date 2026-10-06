import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('whitelist_audit',
    Path(__file__).resolve().parents[1] / 'tools/whitelist_audit.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class WhitelistAuditTests(unittest.TestCase):
    def test_membership_is_only_an_observation(self):
        data = b'8.8.8.0/24\n8.8.8.0/24 # duplicate\n1.1.1.1\n2606:4700::/32\n'
        for ip, expected in [('8.8.8.8', ['8.8.8.0/24']),
                             ('8.8.9.1', []), ('1.1.1.1', ['1.1.1.1/32']),
                             ('2606:4700::1111', ['2606:4700::/32'])]:
            with self.subTest(ip=ip):
                report = tool.inspect(ip, data, {'ref': 'fixture'})
                self.assertEqual(report['matching_cidrs'], expected)
                self.assertEqual(report['source']['network_count'], 3)
                self.assertEqual(report['operator_reachability'], 'not_tested')
                self.assertEqual(report['vless_session'], 'not_tested')
                self.assertFalse(report['routing_changed'])

    def test_malformed_empty_and_catchall_lists_are_rejected(self):
        for data in (b'', b'# comment', b'8.8.8.0/24\n<script>', b'0.0.0.0/0',
                     b'::/0', b'8.8.8.1/24', b'\xff', b'x' * (tool.MAX_BYTES + 1)):
            with self.subTest(data=data[:40]):
                with self.assertRaises((ValueError, UnicodeError)):
                    tool.parse_networks(data)

    def test_private_and_invalid_targets_are_not_downloaded(self):
        for ip in ('127.0.0.1', '10.0.0.1', '::1', 'not-an-ip'):
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    tool.inspect(ip, b'8.8.8.0/24', {})

    def test_only_explicit_commit_can_select_the_fixed_upstream(self):
        with patch.object(tool.urllib.request, 'urlopen') as request:
            for ref in ('main', 'latest', '../', 'a' * 39, 'https://example.com'):
                with self.assertRaises(ValueError):
                    tool.fetch(ref, 10)
            request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
