import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('half_close_baseline', Path(__file__).with_name('half-close-baseline.py'))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class HalfCloseBaselineTests(unittest.TestCase):
    def test_unsupported_requires_complete_upload_and_healthy_control(self):
        self.assertEqual(baseline.classify(True, False, {'uploadedBytes': len(baseline.BODY)}), 'unsupported_eof_response')
        self.assertEqual(baseline.classify(False, False, {'uploadedBytes': len(baseline.BODY)}), 'control_failed')
        self.assertEqual(baseline.classify(True, False, {'uploadedBytes': 0}), 'inconclusive')
        self.assertEqual(baseline.classify(True, False, {}), 'inconclusive')
        self.assertEqual(baseline.classify(True, True, {'uploadedBytes': len(baseline.BODY)}), 'supported')

    def test_control_has_only_socks_and_freedom(self):
        config = baseline.config(12345)
        self.assertEqual(config['inbounds'][0]['protocol'], 'socks')
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')
        self.assertEqual(config['inbounds'][0]['port'], 12345)
        self.assertEqual(config['outbounds'], [{'protocol': 'freedom', 'settings': {}}])
        self.assertNotIn('policy', config)

    def test_fixture_upload_is_stress_probe_size(self):
        self.assertEqual(len(baseline.BODY), 4096)


if __name__ == '__main__':
    unittest.main()
