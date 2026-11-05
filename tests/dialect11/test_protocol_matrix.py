#!/usr/bin/env python3
"""Offline harness contract tests. No processes, listeners or remote services."""
import copy
import base64
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('protocol_matrix', Path(__file__).with_name('protocol-matrix.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class FixtureContract(unittest.TestCase):
    @staticmethod
    def require(ok, detail):
        if not ok:
            raise AssertionError(detail)

    def test_udp_diagnostics_parse_only_counters_and_local_ports(self):
        snmp = 'Ip: Forwarding DefaultTTL\nIp: 1 64\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors\nUdp: 10 2 3 9 1\n'
        self.assertEqual(m.parse_udp_snmp(snmp), {'InDatagrams': 10, 'NoPorts': 2, 'InErrors': 3, 'OutDatagrams': 9, 'RcvbufErrors': 1})
        table = ('sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n'
                 '5: 0100007F:2A38 01020304:FFFF 07 00000004:00000008 00:00000000 00000000 123 0 456 2 SECRET_POINTER 7\n')
        rows = m.parse_udp_socket_table(table, 'udp4')
        self.assertEqual(rows, [{'family': 'udp4', 'localPort': 10808, 'txQueueBytes': 4, 'rxQueueBytes': 8, 'drops': 7}])
        self.assertNotIn('SECRET', repr(rows))
        self.assertNotIn('FFFF', repr(rows))
        before = {'udp4': {'InErrors': 1}, 'udp6': {}, 'sockets': rows}
        after = {'udp4': {'InErrors': 4}, 'udp6': {}, 'sockets': [dict(rows[0], drops=10, rxQueueBytes=0)]}
        delta = m.udp_delta(before, after)
        self.assertEqual(delta['udp4']['InErrors'], 3)
        self.assertEqual(delta['sockets'][0]['dropsDelta'], 3)
        after['sockets'][0]['drops'] = 0
        self.assertIsNone(m.udp_delta(before, after)['sockets'][0]['dropsDelta'])

    def test_exact_failure_records_received_bytes_without_retry(self):
        class Fake:
            def __init__(self):
                self.chunks = [b'abc', b'de', b'']
                self.calls = 0
            def recv(self, _):
                self.calls += 1
                return self.chunks.pop(0)
        sock = Fake()
        with self.assertRaises(m.TransferReadError) as caught:
            m.exact(sock, 8, {'phase': 'duplex-download-body', 'direction': 'download'})
        self.assertEqual(caught.exception.progress['receivedBytes'], 5)
        self.assertEqual(caught.exception.progress['expectedBytes'], 8)
        self.assertEqual(caught.exception.progress['reason'], 'EOF')
        self.assertEqual(sock.calls, 3)

    def test_inline_openvpn_formats_preserve_material_and_overrides(self):
        settings = {'server': {'address': '127.0.0.1', 'port': 1194, 'network': 'tcp'},
                    'advanced': {'dev': 'tun', 'nobind': True, 'remoteCertTls': 'server', 'mtu': 1400},
                    'auth': {'user': 'correct-user', 'pass': 'correct-password'},
                    'crypto': {'dataCiphers': ['AES-256-GCM', 'AES-128-GCM'], 'authHash': 'SHA256'},
                    'certificates': {'ca': 'CA\r\n', 'cert': 'CERT\n', 'key': 'KEY\n', 'tlsAuth': 'CONTROL\n', 'keyDirection': 1},
                    'clientProof': {'keyId': 'unit', 'key': 'ab' * 32}, 'domainStrategy': 'ForceIPv4'}
        before = copy.deepcopy(settings)
        texts = []
        for form in ('string', 'array', 'base64'):
            result = m.openvpn_inline_settings(settings, form, {'username': 'wrong-inline', 'password': 'wrong-inline'})
            text = base64.b64decode(result['ovpnBase64']).decode() if form == 'base64' else ('\n'.join(result['ovpn']) + '\n' if form == 'array' else result['ovpn'])
            texts.append(text)
            self.assertNotIn('server', result)
            self.assertNotIn('advanced', result)
            self.assertNotIn('auth', result)
            self.assertEqual(result['mtu'], 1400)
            self.assertEqual(result['username'], 'correct-user')
            self.assertEqual(result['password'], 'correct-password')
            self.assertEqual(result['clientProof'], settings['clientProof'])
            self.assertIn('data-ciphers AES-256-GCM:AES-128-GCM\n', text)
            self.assertIn('<ca>\nCA\n</ca>', text)
            self.assertIn('<tls-auth>\nCONTROL\n</tls-auth>', text)
            self.assertIn('key-direction 1\n', text)
            self.assertIn('<auth-user-pass>\nwrong-inline\nwrong-inline\n</auth-user-pass>', text)
        self.assertEqual(texts[0], texts[1])
        self.assertEqual(texts[1], texts[2])
        self.assertEqual(settings, before)

    def test_keyfile_variants_do_not_modify_original_export(self):
        config = {'outbounds': [{'tag': 'proxy', 'protocol': 'openvpn', 'settings': {
            'clientProof': {'keyId': 'unit-proof', 'key': 'ab' * 32}}}]}
        before = copy.deepcopy(config)
        with patch.object(m, 'h', SimpleNamespace(require=self.require)):
            for mode in ('valid', 'missing', 'wrong'):
                with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                    result = m.outbound_variant(config, {'proofKeyFile': mode}, Path(folder))
                    proof = result['outbounds'][0]['settings']['clientProof']
                    self.assertNotIn('key', proof)
                    path = Path(proof['keyFile'])
                    if mode == 'missing':
                        self.assertFalse(path.exists())
                    else:
                        value = path.read_text().strip()
                        self.assertEqual(len(value), 64)
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(value == 'ab' * 32, mode == 'valid')
        self.assertEqual(config, before)

    def test_carrier_patch_selects_only_requested_outbound(self):
        config = {'outbounds': [{'tag': 'proxy', 'protocol': 'shadowsocks', 'settings': {'password': 'synthetic'}},
                                {'tag': 'carrier', 'protocol': 'shadowtls', 'settings': {'serverName': 'right.test', 'caPem': 'CA'}}]}
        with patch.object(m, 'h', SimpleNamespace(require=self.require)):
            result = m.outbound_variant(config, {'outboundProtocolSettings': {'shadowtls': {'allowInsecure': True, 'caPem': None}}}, Path('/unused'))
        self.assertEqual(result['outbounds'][0], config['outbounds'][0])
        self.assertTrue(result['outbounds'][1]['settings']['allowInsecure'])
        self.assertNotIn('caPem', result['outbounds'][1]['settings'])
        self.assertEqual(config['outbounds'][1]['settings']['caPem'], 'CA')

    def test_transfer_payload_is_exact_bounded_and_direction_specific(self):
        for size in (1, 256, 32768, 1048576):
            upload = m.transfer_payload('upload', size)
            download = m.transfer_payload('download', size)
            self.assertEqual(len(upload), size)
            self.assertEqual(len(download), size)
            self.assertNotEqual(upload, download)
            self.assertEqual(upload, m.transfer_payload('upload', size))
        for size in (0, -1, True, 1.5, m.MAX_TRANSFER_BYTES + 1):
            with self.assertRaises(ValueError):
                m.transfer_payload('upload', size)

    def test_merge_preserves_input_and_deletes_only_requested_field(self):
        original = {'nested': {'key': 'keep', 'remove': 1, 'array': [1, 2]}, 'flag': True}
        before = copy.deepcopy(original)
        output = m.merge(original, {'nested': {'remove': None, 'array': [3]}, 'flag': False})
        self.assertEqual(output, {'nested': {'key': 'keep', 'array': [3]}, 'flag': False})
        self.assertEqual(original, before)

    def test_tls_auth_fixture_uses_actual_key_direction_field(self):
        for direction in (None, 0, 1):
            with self.subTest(direction=direction):
                case = {'settings': {'certificates': {'tlsCrypt': 'old'}, 'clients': [{'tlsCryptV2': 'old'}]}}
                m.control_key(None, case, {'tlsControl': 'tlsAuth', 'tlsAuthDirection': direction})
                certificates = case['settings']['certificates']
                self.assertNotIn('tlsCrypt', certificates)
                self.assertNotIn('tlsCryptV2', case['settings']['clients'][0])
                self.assertNotIn('tlsAuthKeyDirection', certificates)
                if direction is None:
                    self.assertNotIn('keyDirection', certificates)
                else:
                    self.assertEqual(certificates['keyDirection'], direction)
                lines = certificates['tlsAuth'].splitlines()
                self.assertEqual(len(bytes.fromhex(''.join(lines[1:-1]))), 256)

    def test_v2_fixture_uses_distinct_client_and_server_material(self):
        class Panel:
            def api(self, method, path, json):
                if json['kind'] == 'openvpn-tls-crypt-v2-server':
                    return {'serverKey': 'synthetic-server'}
                if json['kind'] == 'openvpn-tls-crypt-v2' and json['serverKey'] == 'synthetic-server':
                    return {'clientKey': 'synthetic-client'}
                raise AssertionError('unexpected credential request')
        case = {'settings': {'certificates': {'tlsAuth': 'old', 'keyDirection': 0}, 'clients': [{}]}}
        m.control_key(Panel(), case, {'tlsControl': 'tlsCryptV2'})
        self.assertEqual(case['settings']['certificates'], {'tlsCryptV2': 'synthetic-server'})
        self.assertEqual(case['settings']['clients'], [{'tlsCryptV2': 'synthetic-client'}])

    def test_fixture_preserves_option_patch_and_caps_limit_stress(self):
        seed = {'protocol': 'anytls', 'settings': {'clients': [{'password': 'old'}], 'maxStreams': 128}, 'stream': {}}
        before = copy.deepcopy(seed)
        scenario = {'name': 'fixture-contract', 'protocol': 'anytls', 'base': 'seed',
                    'settings': {'maxStreams': 1}, 'client': {'password': 'new', 'uuidHashMiddle': False},
                    'concurrentStreams': 4, 'ipv6': True, 'sustainSeconds': 15, 'listen': '::1', 'halfClose': True,
                    'transferBytes': 32768, 'transferTimeoutSeconds': 60}
        case = m.fixture(None, scenario, {'seed': seed}, 0)
        self.assertEqual(seed, before)
        self.assertEqual(case['settings']['maxStreams'], 1)
        self.assertEqual(case['settings']['clients'][0]['password'], 'new')
        self.assertFalse(case['settings']['clients'][0]['uuidHashMiddle'])
        self.assertEqual(case['concurrentStreams'], 1)
        self.assertTrue(case['ipv6'])
        self.assertEqual(case['sustainSeconds'], 15)
        self.assertEqual(case['listen'], '::1')
        self.assertTrue(case['halfClose'])
        self.assertEqual(case['transferBytes'], 32768)
        self.assertEqual(case['transferTimeoutSeconds'], 60)
        self.assertFalse(case['singleFlowCapacity'], 'AnyTLS limit is per carrier, not global')

    def test_minimum_capacity_is_tested_without_raising_limits(self):
        for protocol, settings in (
            ('openvpn', {'clients': [{}], 'limits': {'maxSessions': 1, 'maxFlowsPerSession': 1}}),
            ('dnstt', {'clients': [{}], 'maxSessions': 1, 'maxStreams': 1}),
        ):
            with self.subTest(protocol=protocol):
                seed = {'protocol': protocol, 'settings': settings, 'stream': {}}
                before = copy.deepcopy(seed)
                case = m.fixture(None, {'name': protocol + '-limits', 'protocol': protocol, 'base': 'seed'}, {'seed': seed}, 0)
                self.assertTrue(case['singleSessionCapacity'])
                self.assertTrue(case['singleFlowCapacity'])
                self.assertEqual(seed, before)
                if protocol == 'openvpn':
                    self.assertEqual(case['settings']['limits'], settings['limits'])
                else:
                    self.assertEqual(case['settings']['maxStreams'], 1)
                    self.assertEqual(case['settings']['maxSessions'], 1)


if __name__ == '__main__':
    unittest.main()
