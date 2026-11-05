#!/usr/bin/env python3
"""Read-only compare archive user/config data with a completed generated-profile restore.

Permits the one additional OpenVPN client intentionally issued after restore by
that harness. Compares every backed-up client field and all server settings.
Traffic counters can increase during post-restore transfer tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--backup', type=Path, required=True)
p.add_argument('--restored', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()

def connect(path):
    c = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
    c.row_factory = sqlite3.Row
    return c

def rows(c, table):
    return [dict(row) for row in c.execute('SELECT * FROM "' + table + '" ORDER BY id')]

checks = []
def check(name, condition):
    checks.append({'name': name, 'passed': bool(condition)})
    if not condition:
        raise AssertionError(name)

result = {'passed': False, 'checks': checks}
try:
    with tempfile.TemporaryDirectory(prefix='xui-backup-compare-') as tmp:
        tmp = Path(tmp)
        with zipfile.ZipFile(a.backup) as z:
            source = tmp / 'backup.db'
            source.write_bytes(z.read('database.db'))
            source.chmod(0o600)
        with connect(source) as before, connect(a.restored) as after:
            check('panel-users-and-password-hashes', rows(before, 'users') == rows(after, 'users'))
            old_rows = rows(before, 'inbounds')
            new_rows = {r['id']: r for r in rows(after, 'inbounds')}
            check('inbound-count', len(old_rows) == len(new_rows))
            protocols = {r['protocol'] for r in old_rows}
            check('all-five-protocols-present', {'openvpn', 'anytls', 'shadowtls', 'dnstt', 'mieru'} <= protocols)
            for old in old_rows:
                new = new_rows[old['id']]
                label = old['protocol'] + '.' + str(old['id'])
                for key in ('user_id', 'total', 'remark', 'enable', 'expiry_time', 'traffic_reset', 'last_traffic_reset_time', 'listen', 'port', 'protocol', 'stream_settings', 'tag', 'sniffing'):
                    check(label + '.inbound.' + key, old[key] == new[key])
                old_settings, new_settings = json.loads(old['settings']), json.loads(new['settings'])
                old_clients = old_settings.pop('clients', [])
                new_clients = new_settings.pop('clients', [])
                check(label + '.server-material-and-unknown-settings', old_settings == new_settings)
                check(label + '.client-count', len(new_clients) == len(old_clients) + (1 if old['protocol'] == 'openvpn' else 0))
                by_email = {c['email']: c for c in new_clients}
                for client in old_clients:
                    check(label + '.client-' + hashlib.sha256(client['email'].encode()).hexdigest()[:12], by_email.get(client['email']) == client)
            old_settings = {r['key']: r['value'] for r in rows(before, 'settings')}
            new_settings = {r['key']: r['value'] for r in rows(after, 'settings')}
            # Profile restoration does not intentionally edit these panel/user
            # choices; runtime generated counters are handled separately.
            for key in ('webPort', 'webBasePath', 'webListen', 'webDomain', 'subPort', 'subJsonPath', 'subEnable', 'subJsonEnable', 'xrayTemplateConfig'):
                if key in old_settings:
                    check('panel-setting.' + key, old_settings[key] == new_settings.get(key))
        result['passed'] = True
except Exception as exc:
    result['error'] = str(exc)
finally:
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    a.output.chmod(0o600)
print(json.dumps({'passed': result['passed'], 'checks': len(checks), 'report': str(a.output)}))
raise SystemExit(0 if result['passed'] else 1)
