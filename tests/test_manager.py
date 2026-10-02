import base64
import copy
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

spec = importlib.util.spec_from_file_location('manager', Path(__file__).resolve().parents[1] / 'manager.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.state = m.initial_state('8.8.4.4', 3)

    def test_numbered_provisioning_and_retry_preserve_credentials(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(m, 'ROOT', Path(temp)):
            state = m.initial_state('8.8.4.4')
            for count in range(1, 6):
                result = m.provision(state, count)
                self.assertEqual([c['name'] for c in result['clients']], [str(n) for n in range(1, count + 1)])
                self.assertEqual(result['clients'][0], state['clients'][0])
                self.assertEqual(m.provision(result, count), result)
                self.assertEqual(len({c['id'] for c in result['clients']}), count)
                self.assertEqual(len({c['token'] for c in result['clients']}), count)
            for invalid in (0, 6, -1, True, '3'):
                with self.assertRaises(ValueError): m.provision(state, invalid)
            (Path(temp) / 'installed').touch()
            with self.assertRaises(ValueError): m.provision(state, 2)

    def test_independent_credentials_and_valid_subscription(self):
        m.validate(self.state)
        users = self.state['clients']
        self.assertEqual(len({c['id'] for c in users}), 3)
        self.assertEqual(len({c['token'] for c in users}), 3)
        for c in users:
            u = urlparse(m.uri(self.state, c))
            q = parse_qs(u.query)
            self.assertEqual(u.username, c['id'])
            self.assertEqual(u.port, 443)
            self.assertEqual(q['path'], [self.state['path']])
            self.assertEqual(q['security'], ['tls'])
            self.assertNotIn('flow', q)
        self.assertTrue(all(c['flow'] == '' for c in m.config(self.state)['inbounds'][0]['settings']['clients']))

    def test_untrusted_state_rejected(self):
        for key, value in [('ip', '127.0.0.1'), ('path', '/x; malicious'), ('schema', 99)]:
            bad = copy.deepcopy(self.state); bad[key] = value
            with self.assertRaises(ValueError): m.validate(bad)
        duplicate = copy.deepcopy(self.state)
        duplicate['clients'].append(duplicate['clients'][0])
        with self.assertRaises(ValueError): m.validate(duplicate)
        with self.assertRaises(ValueError): m.client('../secret')

    def test_atomic_secret_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'state.json'
            m.atomic(p, 'first'); m.atomic(p, 'second')
            self.assertEqual(p.read_text(), 'second')
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_failed_apply_restores_original_config(self):
        changed = copy.deepcopy(self.state)
        changed['clients'].append(m.client('test'))
        with patch.object(m, 'load', return_value=self.state), patch.object(m, 'render') as render, \
             patch.object(m, 'run', side_effect=[RuntimeError('invalid config'), None, None]), \
             patch.object(m, 'atomic') as save:
            with self.assertRaises(RuntimeError): m.apply(changed)
            self.assertEqual(render.call_args_list[0].args[0], changed)
            self.assertEqual(render.call_args_list[1].args[0], self.state)
            save.assert_not_called()

    def test_restore_keeps_new_ip_and_old_credentials_without_extracting(self):
        old = copy.deepcopy(self.state)
        new = m.initial_state('1.1.1.1')
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'state.json'
            source.write_text(json.dumps(old))
            archive = Path(temp) / 'backup.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar: tar.add(source, arcname='state.json')
            with patch.object(m, 'load', return_value=new), patch.object(m, 'backup'), \
                 patch.object(m, 'apply') as apply, patch.object(m, 'links'):
                m.restore(archive)
                restored = apply.call_args.args[0]
                self.assertEqual(restored['ip'], new['ip'])
                self.assertEqual(restored['clients'], old['clients'])
                self.assertEqual(restored['path'], old['path'])

    def test_nginx_hides_subscription_listing_and_logs(self):
        text = m.nginx(self.state)
        self.assertIn('access_log off;', text)
        self.assertIn('try_files $uri =404;', text)
        self.assertNotIn('autoindex on', text)
        self.assertNotIn('listen 443', m.nginx(self.state, tls=False))


if __name__ == '__main__': unittest.main()
