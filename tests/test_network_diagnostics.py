import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('network_diagnostics',
    Path(__file__).resolve().parents[1] / 'tools/network_diagnostics.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class DiagnosticsTests(unittest.TestCase):
    def test_only_read_only_sysctl_queries(self):
        with patch.object(tool.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 0, 'bbr\n', '')) as run:
            data = tool.collect()
        self.assertEqual(data['scope'], 'local_read_only_no_external_probes')
        self.assertEqual(len(run.call_args_list), 3)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:2], ['sysctl', '-n'])
            self.assertNotIn('-w', call.args[0])
        self.assertNotIn('xray', data)

    def test_summary_does_not_expose_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            path.write_text(json.dumps({'inbounds': [{
                'protocol': 'vless', 'listen': 'SECRET-IP',
                'settings': {'clients': [{'id': 'SECRET-UUID', 'email': 'SECRET-NAME'}]},
                'streamSettings': {'network': 'ws', 'security': 'tls',
                                   'tlsSettings': {'privateKey': 'SECRET-KEY'}}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {'password': 'SECRET-PASSWORD'}}]}))
            summary = tool.summarize_xray(path)
        self.assertNotIn('SECRET', json.dumps(summary))
        self.assertEqual(summary['inbounds'][0]['transport'], 'ws')

    def test_missing_config_and_sysctl_do_not_claim_success(self):
        self.assertIn('error', tool.summarize_xray('/no-such-sa-vpn-config'))
        with patch.object(tool.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertIsNone(tool.sysctl_value('net.ipv4.tcp_congestion_control'))


if __name__ == '__main__':
    unittest.main()
