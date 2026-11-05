#!/usr/bin/env python3
"""Offline contract tests for the legacy TLS regression runner."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('legacy_tls_regression', Path(__file__).with_name('legacy-tls-regression.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class LegacyClientContract(unittest.TestCase):
    def test_vless_uses_normal_auth_and_explicit_ca(self):
        config = harness.client_config('vless', 29400, '00112233-4455-4677-8899-aabbccddeeff', 'public-test-ca', '1.3')
        outbound = config['outbounds'][0]
        user = outbound['settings']['vnext'][0]['users'][0]
        self.assertEqual(user, {'id': '00112233-4455-4677-8899-aabbccddeeff', 'encryption': 'none'})
        tls = outbound['streamSettings']['tlsSettings']
        self.assertFalse(tls['allowInsecure'])
        self.assertTrue(tls['disableSystemRoot'])
        self.assertEqual(tls['certificates'], [{'certificate': ['public-test-ca'], 'usage': 'verify'}])
        self.assertEqual(tls['minVersion'], tls['maxVersion'])
        self.assertFalse(tls['enableSessionResumption'])

    def test_trojan_uses_normal_auth_and_no_direct_route(self):
        config = harness.client_config('trojan', 29401, 'synthetic-password', 'public-test-ca', '1.2')
        self.assertEqual(config['outbounds'][0]['settings'], {'servers': [{'address': '127.0.0.1', 'port': 29401, 'password': 'synthetic-password'}]})
        self.assertEqual(len(config['outbounds']), 1)
        self.assertEqual(config['routing']['rules'], [])
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')
        self.assertEqual(config['outbounds'][0]['streamSettings']['tlsSettings']['serverName'], 'e2e.test')

    def test_independent_fixtures_share_no_mutable_settings(self):
        first = harness.client_config('trojan', 1, 'one', 'ca-one', '1.2')
        second = harness.client_config('trojan', 2, 'two', 'ca-two', '1.3')
        first['outbounds'][0]['settings']['servers'][0]['password'] = 'changed'
        first['outbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]['certificate'].append('changed')
        self.assertEqual(second['outbounds'][0]['settings']['servers'][0]['password'], 'two')
        self.assertEqual(second['outbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]['certificate'], ['ca-two'])


if __name__ == '__main__':
    unittest.main()
