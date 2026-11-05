#!/usr/bin/env python3
"""Offline tests for packaged-panel tools. No namespace, listener or browser starts."""
import ast
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
PROTOCOLS = ('openvpn', 'anytls', 'shadowtls', 'dnstt', 'mieru')
FIELDS = ('user_id', 'total', 'remark', 'enable', 'expiry_time', 'traffic_reset',
          'last_traffic_reset_time', 'listen', 'port', 'protocol', 'stream_settings', 'tag', 'sniffing')


class PackagedPanelToolsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xui-offline-backup-')
        self.root = Path(self.temp.name)
        self.original = self.root / 'original.db'
        self.restored = self.root / 'restored.db'
        self.archive = self.root / 'backup.zip'
        self.report = self.root / 'result.json'
        for path, extra in ((self.original, False), (self.restored, True)):
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE users(id INTEGER, username TEXT, password TEXT)')
                db.execute("INSERT INTO users VALUES(1, 'synthetic-admin', 'synthetic-hash')")
                db.execute('CREATE TABLE inbounds(id INTEGER, settings TEXT, ' + ','.join('"' + k + '" TEXT' for k in FIELDS) + ')')
                for index, protocol in enumerate(PROTOCOLS, 1):
                    clients = [{'email': protocol + '@example.invalid', 'password': 'synthetic-client-secret', 'comment': 'retain', 'expiryTime': 1234567890, 'totalGB': 10000}]
                    if extra and protocol == 'openvpn':
                        clients.append({'email': 'third-openvpn@example.invalid', 'password': 'synthetic-issued-secret'})
                    settings = {'clients': clients, 'serverMaterial': 'synthetic-server-secret', 'unknownFutureField': {'retain': True}}
                    values = [protocol if key == 'protocol' else str(index) if key in ('port', 'user_id') else '{}' if key in ('stream_settings', 'sniffing') else 'same' for key in FIELDS]
                    db.execute('INSERT INTO inbounds VALUES(' + ','.join('?' for _ in range(2 + len(FIELDS))) + ')', [index, json.dumps(settings), *values])
                db.execute('CREATE TABLE settings(id INTEGER, key TEXT, value TEXT)')
                db.execute("INSERT INTO settings VALUES(1, 'webPort', '28000')")
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.write(self.original, 'database.db')

    def tearDown(self):
        self.temp.cleanup()

    def compare(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'verify-restored-user-data.py'), '--backup', str(self.archive), '--restored', str(self.restored), '--output', str(self.report)], capture_output=True, text=True, check=False)
        # Report and console must describe failures without copying credentials.
        for secret in ('synthetic-hash', 'synthetic-client-secret', 'synthetic-server-secret'):
            self.assertNotIn(secret, result.stdout + result.stderr + self.report.read_text())
        return result.returncode, json.loads(self.report.read_text())

    def test_preserved_metadata_and_intentionally_issued_extra_client(self):
        code, report = self.compare()
        self.assertEqual(code, 0)
        self.assertTrue(report['passed'])
        self.assertGreater(len(report['checks']), 50)

    def test_changed_administrator_hash_is_rejected(self):
        with sqlite3.connect(self.restored) as db:
            db.execute("UPDATE users SET password='changed'")
        code, report = self.compare()
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'panel-users-and-password-hashes')

    def test_changed_client_field_is_rejected(self):
        with sqlite3.connect(self.restored) as db:
            value = json.loads(db.execute('SELECT settings FROM inbounds WHERE id=2').fetchone()[0])
            value['clients'][0]['comment'] = 'lost metadata'
            db.execute('UPDATE inbounds SET settings=? WHERE id=2', (json.dumps(value),))
        code, report = self.compare()
        self.assertEqual(code, 1)
        self.assertIn('anytls.2.client-', report['error'])

    def test_unknown_server_field_loss_is_rejected(self):
        with sqlite3.connect(self.restored) as db:
            value = json.loads(db.execute('SELECT settings FROM inbounds WHERE id=3').fetchone()[0])
            del value['unknownFutureField']
            db.execute('UPDATE inbounds SET settings=? WHERE id=3', (json.dumps(value),))
        code, report = self.compare()
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'shadowtls.3.server-material-and-unknown-settings')

    def test_missing_protocol_is_rejected(self):
        with sqlite3.connect(self.restored) as db:
            db.execute('DELETE FROM inbounds WHERE id=5')
        code, report = self.compare()
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'inbound-count')

    def test_tool_syntax_and_relocatable_help(self):
        for filename in ('packaged-panel-browser.py', 'verify-restored-user-data.py'):
            ast.parse((HERE / filename).read_text())
            result = subprocess.run([sys.executable, '-B', str(HERE / filename), '--help'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('/root/', result.stdout)
        if shutil.which('node'):
            subprocess.run(['node', '--check', str(HERE / 'packaged-panel-browser.js')], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
