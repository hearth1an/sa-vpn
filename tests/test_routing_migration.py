import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('routing_migration',
    Path(__file__).resolve().parents[1] / 'tools/apply_happ_routing_3xui.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'x-ui.db'
        self.runtime = self.root / 'config.json'
        with sqlite3.connect(self.db) as db:
            db.execute('create table settings(key text primary key, value text)')
            db.execute('create table inbounds(id integer primary key, settings text)')
            db.execute('insert into settings values(?, ?)', ('unrelated', 'preserve'))
            db.execute('insert into settings values(?, ?)', ('subEnableRouting', 'false'))
            db.execute('insert into inbounds values(?, ?)', (1, 'private-user-fixture'))
        self.inbounds = [{'protocol': 'vless', 'settings': {'clients': [{'id': 'private-fixture'}]}}]
        self.runtime.write_text(json.dumps({'inbounds': self.inbounds}))

    def settings(self):
        with sqlite3.connect(self.db) as db:
            return dict(db.execute('select key,value from settings').fetchall())

    def test_success_preserves_keys_and_private_backup(self):
        original = self.settings()
        with patch.object(tool.subprocess, 'run') as run, patch.object(tool.time, 'sleep'):
            backup = tool.apply_profile(tool.PROFILE, self.db, self.runtime)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(backup) as db:
            self.assertEqual(dict(db.execute('select key,value from settings')), original)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('select * from inbounds').fetchall(), [(1, 'private-user-fixture')])
        self.assertEqual(json.loads(self.runtime.read_text())['inbounds'], self.inbounds)
        self.assertEqual(self.settings()['unrelated'], 'preserve')
        self.assertEqual(self.settings()['subRoutingRules'], tool.routing_link())
        self.assertEqual(len(run.call_args_list), 2)

    def test_restart_failure_restores_absent_and_existing_settings(self):
        original = self.settings()
        with patch.object(tool.subprocess, 'run', side_effect=[
                subprocess.CalledProcessError(1, 'systemctl'), None]), patch.object(tool.time, 'sleep'):
            with self.assertRaises(subprocess.CalledProcessError):
                tool.apply_profile(tool.PROFILE, self.db, self.runtime)
        self.assertEqual(self.settings(), original)

    def test_changed_runtime_inbounds_trigger_rollback(self):
        original = self.settings()
        def restart(*args, **kwargs):
            self.runtime.write_text(json.dumps({'inbounds': []}))
        with patch.object(tool.subprocess, 'run', side_effect=restart), patch.object(tool.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'VPN-входы'):
                tool.apply_profile(tool.PROFILE, self.db, self.runtime)
        self.assertEqual(self.settings(), original)

    def test_wrong_schema_is_not_mutated(self):
        wrong = self.root / 'wrong.db'
        with sqlite3.connect(wrong) as db:
            db.execute('create table arbitrary(value text)')
        with patch.object(tool.subprocess, 'run') as run:
            with self.assertRaises(sqlite3.OperationalError):
                tool.apply_profile(tool.PROFILE, wrong, self.runtime)
        run.assert_not_called()
        self.assertEqual(list(self.root.glob('wrong.db.before-routing-*.bak')), [])

    def test_changed_database_keys_are_detected(self):
        original = self.settings()
        def restart(*args, **kwargs):
            if args[0] == ['systemctl', 'restart', 'x-ui']:
                with sqlite3.connect(self.db) as db:
                    db.execute('update inbounds set settings=?', ('unexpected',))
        with patch.object(tool.subprocess, 'run', side_effect=restart), patch.object(tool.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'пользователей'):
                tool.apply_profile(tool.PROFILE, self.db, self.runtime)
        self.assertEqual(self.settings(), original)
        # Unexpected external inbound changes are NOT silently overwritten.
        # A full private backup remains available for operator-led recovery.
        self.assertEqual(len(list(self.root.glob('x-ui.db.before-routing-*.bak'))), 1)


if __name__ == '__main__':
    unittest.main()
