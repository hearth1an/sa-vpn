import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('monitor', Path(__file__).resolve().parents[1] / 'monitoring/check.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.nodes = {f'{c}{i}': {'location': [c], 'asn': str(i)}
                      for c in ('ru', 'de') for i in (1, 2, 3)}
        self.good = [{'time': 0.04, 'address': '8.8.8.8'}]
        self.bad = [{'error': 'Connection timed out'}]

    def test_regional_failure_vs_global_outage(self):
        results = {n: self.bad if n.startswith('ru') else self.good for n in self.nodes}
        self.assertEqual(m.classify(self.nodes, results)[0], 'possible_regional_block')
        self.assertEqual(m.classify(self.nodes, {n: self.bad for n in self.nodes})[0], 'server_unreachable')

    def test_missing_results_are_not_failed_probes(self):
        results = {n: self.good for n in self.nodes if not n.startswith('ru')}
        self.assertEqual(m.classify(self.nodes, results)[0], 'monitor_inconclusive')
        self.assertEqual(m.tcp_status(None), 'unknown')
        self.assertEqual(m.tcp_status([{}]), 'unknown')

    def test_mixed_russian_networks_are_degradation(self):
        results = {n: self.good for n in self.nodes}; results['ru1'] = self.bad
        self.assertEqual(m.classify(self.nodes, results)[0], 'regional_degradation')

    def test_single_failed_round_is_not_confirmed_block(self):
        with patch.object(m, 'probe', side_effect=[{'status': 'possible_regional_block'}, {'status': 'healthy'}]), \
             patch.object(m.time, 'sleep'):
            self.assertEqual(m.check({'ip': '8.8.8.8'})['status'], 'transient')

    def test_independent_asn_selection(self):
        nodes = dict(self.nodes)
        nodes['ru4'] = {'location': ['ru'], 'asn': '1'}
        selected = m.choose_nodes(nodes)
        ru = [v['asn'] for v in selected.values() if v['location'][0] == 'ru']
        self.assertEqual(len(ru), len(set(ru)))


if __name__ == '__main__': unittest.main()
