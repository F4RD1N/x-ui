#!/usr/bin/env python3
"""Real panel API + native core loopback E2E. Invoke via run-panel-e2e.sh.

Every fixture is newly generated, every target is loopback, and all processes
run in one private network namespace. Preserves logs and JSON result evidence.
It never opens installed DBs/configs or changes host service/firewall state.
"""
import argparse
import base64
import copy
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import zipfile

import requests

UUID = '00112233-4455-4677-8899-aabbccddeeff'
PANEL_PORT, SUB_PORT, HTTP_PORT, TLS_PORT, UDP_PORT = 28000, 28001, 28002, 28003, 28004
CLIENT_SOCKS, CLIENT_UDP = 28005, 28006
TARGET = '198.18.0.1'  # Local benchmark-range address assigned only inside the test netns.
BODY = b'dialect11-local-e2e-' + bytes(range(256)) * 64
RESULTS = []
PROCESSES = []
WORK_CREATED = False


def result(name, ok, detail=''):
    RESULTS.append({'name': name, 'ok': bool(ok), 'detail': str(detail)[:600]})
    print(('PASS ' if ok else 'FAIL ') + name + (': ' + str(detail)[:300] if detail else ''), flush=True)


def require(ok, detail):
    if not ok:
        raise AssertionError(detail)


def wait_port(port, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=.2).close()
            return True
        except OSError:
            time.sleep(.1)
    return False


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def launch(args, cwd, log, env=None):
    with open(log, 'ab', buffering=0) as f:
        p = subprocess.Popen([str(v) for v in args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=f, stderr=f, start_new_session=True)
    PROCESSES.append(p)
    return p


def stop(p):
    if p is None or getattr(p, '_e2e_stopped', False):
        return
    p._e2e_stopped = True
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=5)
    # Also reap panel descendants that might outlive their parent.
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def openssl(folder, *args):
    subprocess.run(['openssl', *args], cwd=folder, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def certificates(folder):
    folder.mkdir(parents=True, exist_ok=True)
    openssl(folder, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-subj', '/CN=E2E CA', '-days', '2', '-keyout', 'ca.key', '-out', 'ca.crt')
    for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        openssl(folder, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-subj', '/CN=' + name, '-keyout', name + '.key', '-out', name + '.csr')
        (folder / (name + '.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=' + usage +
                                              '\nsubjectAltName=DNS:e2e.test,DNS:cover.test,IP:127.0.0.1\n')
        openssl(folder, 'x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-CAcreateserial', '-days', '2', '-extfile', name + '.ext', '-out', name + '.crt')
    return {p.name: p.read_text() for p in folder.glob('*') if p.suffix in ('.key', '.crt')}


class EchoHTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/large'):
            body = BODY * 64
        else:
            body = BODY
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_targets(fixtures):
    servers = []
    for port, tls in [(HTTP_PORT, False), (TLS_PORT, True)]:
        srv = http.server.ThreadingHTTPServer(('127.0.0.1' if tls else TARGET, port), EchoHTTP)
        srv.daemon_threads = True
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(fixtures / 'server.crt', fixtures / 'server.key')
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((TARGET, UDP_PORT))
    def echo():
        while True:
            try:
                data, peer = udp.recvfrom(65535)
                udp.sendto(data, peer)
            except OSError:
                return
    threading.Thread(target=echo, daemon=True).start()
    return servers, udp


def base_template():
    return {'log': {'loglevel': 'warning'}, 'api': {'tag': 'api', 'services': ['HandlerService', 'StatsService']},
            'inbounds': [{'tag': 'api', 'listen': '127.0.0.1', 'port': 28009, 'protocol': 'tunnel', 'settings': {'address': '127.0.0.1'}}],
            'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'blocked', 'protocol': 'blackhole'}],
            'routing': {'rules': [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'}]},
            'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}},
                       'system': {'statsInboundUplink': True, 'statsInboundDownlink': True}}, 'stats': {}}


class Panel:
    def __init__(self, root, panel_bin, core_bin, arch='amd64'):
        self.root = root
        self.db = root / 'db'
        self.bin = root / 'bin'
        self.logs = root / 'logs'
        for p in (self.db, self.bin, self.logs):
            p.mkdir(parents=True, exist_ok=True)
        shutil.copy2(core_bin, self.bin / ('xray-linux-' + arch))
        self.env = dict(os.environ, XUI_DB_FOLDER=str(self.db), XUI_BIN_FOLDER=str(self.bin),
                        XUI_LOG_FOLDER=str(self.logs), XUI_LOG_LEVEL='debug')
        self.panel_bin = panel_bin
        self.p = None
        self.http = requests.Session()
        self.http.trust_env = False
        self.url = f'http://127.0.0.1:{PANEL_PORT}/e2e'
        self.sub_port = SUB_PORT
        self.sub_path = '/json/'

    def init(self):
        subprocess.run([str(self.panel_bin), 'setting', '-port', str(PANEL_PORT), '-listenIP', '127.0.0.1',
                        '-webBasePath', '/e2e/', '-username', 'e2e-admin', '-password', 'e2e-only-private-namespace'],
                       env=self.env, cwd=self.root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        db_path = self.db / 'x-ui.db'
        con = sqlite3.connect(db_path)
        for k, v in {'subListen': '127.0.0.1', 'subPort': str(SUB_PORT), 'subJsonEnable': 'true', 'subClashEnable': 'false',
                     'subEnableRouting': 'false', 'subEncrypt': 'false', 'xrayTemplateConfig': json.dumps(base_template())}.items():
            cur = con.execute('UPDATE settings SET value=? WHERE key=?', (v, k))
            if cur.rowcount == 0:
                con.execute('INSERT INTO settings(key,value) VALUES(?,?)', (k, v))
        con.commit()
        con.close()

    def start(self):
        self.p = launch([self.panel_bin, 'run'], self.root, self.logs / 'panel.log', self.env)
        require(wait_port(PANEL_PORT, 20), 'panel HTTP did not listen')
        require(wait_port(SUB_PORT, 20), 'subscription HTTP did not listen')
        self.login()

    def login(self):
        self.http.cookies.clear()
        self.api('POST', '/login', data={'username': 'e2e-admin', 'password': 'e2e-only-private-namespace'})

    def api(self, method, path, **kwargs):
        r = self.http.request(method, self.url + path, timeout=90, **kwargs)
        r.raise_for_status()
        j = r.json()
        require(j.get('success'), f'{method} {path}: {j.get("msg", "failed")}')
        return j.get('obj')

    def restart(self):
        self.api('POST', '/panel/api/server/restartXrayService')
        time.sleep(.25)

    def export(self, sub_id):
        r = self.http.get(f'http://127.0.0.1:{self.sub_port}{self.sub_path}{sub_id}', timeout=20)
        r.raise_for_status()
        j = r.json()
        if isinstance(j, list):
            require(len(j) == 1, 'subscription must contain exactly selected fixture')
            j = j[0]
        require('outbounds' in j, 'subscription has no outbounds')
        return j


def wait_restore_reload(panel, reply, label, sub_port=SUB_PORT, sub_path='/json/'):
    require(isinstance(reply, dict) and reply.get('restored') and reply.get('restarting'), 'restore did not schedule settings activation')
    delay = reply.get('restartAfterSeconds')
    require(isinstance(delay, (int, float)) and 0 <= delay <= 10, 'unexpected restore reload delay')
    url = urllib.parse.urljoin(panel.url + '/', reply.get('url', ''))
    parsed = urllib.parse.urlsplit(url)
    require(parsed.hostname == '127.0.0.1' and parsed.scheme == 'http', 'unexpected restore target URL')
    time.sleep(delay + 1)
    panel.url = url.rstrip('/')
    panel.sub_port, panel.sub_path = sub_port, sub_path
    require(wait_port(parsed.port, 20) and wait_port(sub_port, 20), 'restored HTTP listeners not running')
    end = time.monotonic() + 15
    while True:
        try:
            panel.login()
            break
        except Exception:
            if time.monotonic() >= end:
                raise
            time.sleep(.25)
    result(label, True)


def stopped_listener_restore(panel, cases, exports):
    original = panel.api('POST', '/panel/setting/all')
    survivor = next(c for c in cases if c['name'] in exports)
    # A backed-up HTTP port held by an unrelated local listener must be rejected
    # before it can strand the administrator after the scheduled reload.
    with socket.socket() as blocker:
        blocker.bind(('127.0.0.1', 28012))
        blocker.listen(1)
        occupied = dict(original, webPort=28012)
        panel.api('POST', '/panel/setting/update', json=occupied)
        occupied_backup = panel.http.get(panel.url + '/panel/api/server/getDb', timeout=45)
        occupied_backup.raise_for_status()
        panel.api('POST', '/panel/setting/update', json=original)
        previous_pid = current_core_pid(panel)
        rejection = panel.http.post(panel.url + '/panel/api/server/importDB',
                                    files={'db': ('occupied-listener.zip', occupied_backup.content, 'application/zip')}, timeout=60)
        require(rejection.status_code == 200 and not rejection.json().get('success'), 'occupied panel listener backup was accepted')
        require(current_core_pid(panel) == previous_pid, 'occupied listener rejection changed running core')
        http_probe(survivor['out_socks'])
        result('restore-rejects-occupied-listener-keeps-service', True)
    changed = copy.deepcopy(original)
    changed.update(webPort=28010, webBasePath='/restored-e2e/', subPort=28011, subJsonPath='/restored-json/')
    panel.api('POST', '/panel/setting/update', json=changed)
    blob = panel.http.get(panel.url + '/panel/api/server/getDb', timeout=45)
    blob.raise_for_status()
    require(blob.content[:2] == b'PK', 'changed-settings backup failed')
    panel.api('POST', '/panel/setting/update', json=original)
    panel.api('POST', '/panel/api/server/stopXrayService')
    survivor = next(c for c in cases if c['name'] in exports)
    require(not wait_port(survivor['out_socks'], 1), 'explicit stop left core listening')
    reply = panel.api('POST', '/panel/api/server/importDB', files={'db': ('changed-settings.zip', blob.content, 'application/zip')})
    wait_restore_reload(panel, reply, 'restore-activates-changed-panel-and-sub-settings', 28011, '/restored-json/')
    require(not wait_port(PANEL_PORT, .5) and not wait_port(SUB_PORT, .5), 'old HTTP listeners remained active')
    require(not wait_port(survivor['out_socks'], 1), 'manual stopped core unexpectedly restarted during settings activation')
    require('outbounds' in panel.export(survivor['subid']), 'new subscription route failed')
    result('restore-keeps-manually-stopped-core-stopped', True)
    panel.restart()
    require(wait_port(survivor['out_socks'], 10), 'explicit restart after stopped restore failed')
    http_probe(survivor['out_socks'])
    result('restore-explicit-restart-traffic', True)


def panel_client(email, subid, **fields):
    return dict(email=email, enable=True, subId=subid, totalGB=0, expiryTime=0, limitIp=0, reset=0, **fields)


def make_cases(panel, cert, asset_dir):
    cases = []
    def add(name, protocol, settings, stream=None, udp=True):
        port = 29000 + len(cases)
        subid = 'e2e' + name.replace('-', '')
        for index, user in enumerate(settings.get('clients', [])):
            user.update(panel_client(user.get('email', name + ('' if index == 0 else '-other') + '@example.invalid'),
                                     user.get('subId', subid if index == 0 else subid + 'other')))
        if protocol == 'shadowtls':
            for index, u in enumerate(settings['inner']['settings'].get('clients', [])):
                u.setdefault('email', settings['clients'][min(index, len(settings['clients']) - 1)]['email'])
        cases.append({'name': name, 'protocol': protocol, 'port': port, 'settings': settings,
                      'stream': stream or {}, 'subid': subid, 'udp': udp})
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / 'tls.crt').write_text(cert['server.crt'] + cert['ca.crt'])
    (asset_dir / 'tls.key').write_text(cert['server.key'])
    tls_stream = {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'certificates': [
        {'certificateFile': str(asset_dir / 'tls.crt'), 'keyFile': str(asset_dir / 'tls.key')} ]}}
    for custom in (False, True):
        add('anytls-custom' if custom else 'anytls-normal', 'anytls',
            {'clients': [{'password': UUID if custom else 'e2e/password%with?symbols', 'uuidHashMiddle': custom}],
             'clientExport': {'serverName': 'e2e.test', 'ca': cert['ca.crt']}}, copy.deepcopy(tls_stream))
    for transport, custom in [('tcp', False), ('udp', False), ('tcp', True)]:
        add('mieru-' + transport + ('-custom' if custom else ''), 'mieru',
            {'transport': transport, 'clients': [{'username': UUID if custom else 'e2e/user%?', 'password': 'e2e-pass', 'uuidMetadataTrailer': custom}]})
    for kind in ('vless', 'socks'):
        keys = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'dnstt'})
        user = {'id': UUID} if kind == 'vless' else {'username': 'dns-user', 'password': 'dns-password'}
        add('dnstt-' + kind, 'dnstt', {'domain': 'e2e.test', 'privateKey': keys['privateKey'],
                                     'inner': {'protocol': kind}, 'clients': [user]}, udp=(kind == 'vless'))
    orbit_key = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'orbit', 'certificate': cert['server.crt']})['key']
    for transport in ('tcp', 'ws', 'quic'):
        settings = {'transport': transport, 'clients': [{'key': orbit_key}],
                    'tls': {'certificate': (cert['server.crt'] + cert['ca.crt']).splitlines(), 'key': cert['server.key'].splitlines()}}
        if transport == 'ws':
            settings.update(host='owned.test', path='/core', clientExport={'serverName': '127.0.0.1'})
        add('orbit-' + transport, 'orbit', settings)
    for custom in (False, True):
        add('shadowtls-custom' if custom else 'shadowtls-v3', 'shadowtls',
            {'version': 3, 'strict': True, 'handshake': {'address': '127.0.0.1', 'port': TLS_PORT},
             'clients': [{'password': UUID if custom else 'carrier-pass', 'requireUuidSessionId': custom}],
             'inner': {'protocol': 'vless', 'settings': {'clients': [{'id': UUID}], 'decryption': 'none'}},
             'clientExport': {'serverName': 'e2e.test', 'ca': cert['ca.crt']}})
    for ss2022 in (False, True):
        name = 'shadowtls-ss2022' if ss2022 else 'shadowtls-aead'
        method = '2022-blake3-aes-128-gcm' if ss2022 else 'aes-128-gcm'
        user_keys = [base64.b64encode(bytes([47 + i]) * 16).decode() if ss2022 else 'aead-inner-' + str(i) for i in range(2)]
        inner = {'network': 'tcp', 'method': method,
                 'clients': [({'password': user_keys[i]} if ss2022 else {'method': method, 'password': user_keys[i]}) for i in range(2)]}
        if ss2022:
            inner['password'] = base64.b64encode(bytes([31]) * 16).decode()
        metadata = {'serverName': 'e2e.test', 'ca': cert['ca.crt']}
        if ss2022:
            metadata.update(uot=True, uotVersion=2)
        add(name, 'shadowtls', {'version': 3, 'strict': True, 'handshake': {'address': '127.0.0.1', 'port': TLS_PORT},
                               'clients': [{'password': 'encrypted-carrier-' + str(i)} for i in range(2)],
                               'inner': {'protocol': 'shadowsocks', 'settings': inner}, 'clientExport': metadata}, udp=ss2022)
        cases[-1]['large'] = True
    for network, proof in [('tcp', False), ('udp', False), ('tcp', True)]:
        user = {'commonName': 'client', 'certificate': cert['client.crt'], 'privateKey': cert['client.key']}
        settings = {'network': network, 'clients': [user], 'certificates': {'ca': cert['ca.crt'], 'cert': cert['server.crt'], 'key': cert['server.key']},
                    'crypto': {'dataCiphers': ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], 'authHash': 'SHA256'},
                    'tunnel': {'ipv4': '10.88.0.0/24', 'ipv6': 'fd88::/64', 'mtu': 1400}}
        if proof:
            user['clientProof'] = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'openvpn-proof'})
            settings['clientProof'] = {'required': True}
        add('openvpn-' + network + ('-proof' if proof else ''), 'openvpn', settings)
    add('vless-stock', 'vless', {'clients': [{'id': UUID}], 'decryption': 'none', 'encryption': 'none'})
    add('vless-dialect', 'vless', {'clients': [{'id': UUID}], 'decryption': 'none', 'encryption': 'none', 'dialects': [120]})
    for raw in (False, True):
        add('vmess-raw' if raw else 'vmess-stock', 'vmess', {'clients': [{'id': UUID, 'security': 'auto', 'rawUuidAuth': raw}]})
    add('trojan-stock', 'trojan', {'clients': [{'password': 'trojan-local-password'}]},
        {'network': 'tcp', 'security': 'none'})
    add('trojan-custom', 'trojan', {'clients': [{'password': UUID, 'uuidHashPrefix': True}]}, {'network': 'tcp', 'security': 'none'})
    return cases


def payload(case):
    return {'up': 0, 'down': 0, 'total': 0, 'remark': 'e2e-' + case['name'], 'enable': True,
            'expiryTime': 0, 'trafficReset': 'never', 'lastTrafficResetTime': 0, 'listen': '127.0.0.1',
            'port': case['port'], 'protocol': case['protocol'], 'settings': json.dumps(case['settings']),
            'streamSettings': json.dumps(case['stream']), 'sniffing': json.dumps({'enabled': False})}


def configure_cases(panel, cases, work):
    exports = {}
    for case in cases:
        name = case['name']
        try:
            obj = panel.api('POST', '/panel/api/inbounds/add', json=payload(case))
            case['id'] = obj['id']
            obj = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
            stored = json.loads(obj['settings'])
            require(stored.get('clientExport') == case['settings'].get('clientExport'), 'client export metadata lost on create')
            user = stored['clients'][0]
            for key, value in case['settings']['clients'][0].items():
                require(user.get(key) == value, 'client field lost on create: ' + key)
            obj['remark'] += '-edited'
            panel.api('POST', '/panel/api/inbounds/update/' + str(case['id']), json=obj)
            obj = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
            require(obj['remark'].endswith('-edited'), 'inbound edit not persisted')
            require(json.loads(obj['settings'])['clients'][0] == user, 'inbound edit changed client settings')
            if case['protocol'] not in ('vless', 'vmess', 'trojan'):
                token = 'email:' + base64.urlsafe_b64encode(user['email'].encode()).decode().rstrip('=')
                edited_user = dict(user, comment='E2E edited through path-safe identity')
                panel.api('POST', '/panel/api/inbounds/updateClient/' + token,
                          json={'id': case['id'], 'settings': json.dumps({'clients': [edited_user]})})
                obj = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
                require(json.loads(obj['settings'])['clients'][0].get('comment') == edited_user['comment'], 'client edit not persisted')
            exported = panel.export(case['subid'])
            outbound = next(o for o in exported['outbounds'] if o['tag'] == 'proxy')
            require(outbound['protocol'] not in ('freedom', 'blackhole'), 'export silently lacks protocol')
            if case['name'] in ('shadowtls-aead', 'shadowtls-ss2022'):
                inner = case['settings']['inner']['settings']
                prefix = inner.get('password', '') + ':' if case['name'] == 'shadowtls-ss2022' else ''
                server = outbound['settings']['servers'][0]
                require(server['password'] == prefix + inner['clients'][0]['password'], 'wrong encrypted inner key exported')
                require(inner['clients'][1]['password'] not in json.dumps(exported), 'another user inner key leaked in export')
                if case['name'] == 'shadowtls-ss2022':
                    require(server.get('uot') is True and server.get('uotVersion') == 2, 'SS2022 export lacks current-client UoT v2 fields')
                secondary = panel.export(case['settings']['clients'][1]['subId'])
                second_server = next(o for o in secondary['outbounds'] if o['tag'] == 'proxy')['settings']['servers'][0]
                require(second_server['password'] == prefix + inner['clients'][1]['password'], 'second encrypted inner key exported incorrectly')
                case['secondary_export'] = secondary
                result('encrypted-inner-export-key-binding.' + case['name'], True)
            if case['protocol'] in ('orbit', 'openvpn', 'anytls'):
                require(cert_server_secret not in json.dumps(exported), 'server private key leaked in export')
            exports[name] = exported
            write_json(work / (name + '-export.json'), exported)
            result('api.create-edit-export.' + name, True)
        except Exception as e:
            result('api.create-edit-export.' + name, False, e)
    panel.restart()
    return exports


def client_config(exported, socks=CLIENT_SOCKS, udp=CLIENT_UDP):
    # Preserve actual exported protocol objects byte-for-byte in semantic JSON.
    return {'log': {'loglevel': 'debug'}, 'inbounds': [
        {'tag': 'socks', 'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}},
        {'tag': 'udp', 'listen': '127.0.0.1', 'port': udp, 'protocol': 'dokodemo-door',
         'settings': {'network': 'udp', 'address': TARGET, 'port': UDP_PORT}}],
        'outbounds': copy.deepcopy(exported['outbounds']), 'routing': {'rules': [{'type': 'field', 'inboundTag': ['socks', 'udp'], 'outboundTag': 'proxy'}]}}


def http_probe(port, large=False, timeout=25):
    path = '/large' if large else '/echo'
    proc = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{port}',
                           '--connect-timeout', '8', '--max-time', str(timeout), f'http://{TARGET}:{HTTP_PORT}{path}'], capture_output=True)
    expected = BODY * 64 if large else BODY
    require(proc.returncode == 0, proc.stderr.decode(errors='replace').strip())
    require(proc.stdout == expected, f'HTTP body mismatch: {len(proc.stdout)} bytes vs {len(expected)}')


def udp_probe(port):
    data = b'e2e-udp-' + secrets.token_bytes(200)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        for attempt in range(2):
            sock.sendto(data, ('127.0.0.1', port))
            try:
                got, _ = sock.recvfrom(4096)
                require(got == data, 'UDP payload mismatch')
                return
            except socket.timeout:
                if attempt:
                    raise


def traffic_client(core, exported, case, folder, phase):
    folder.mkdir(parents=True, exist_ok=True)
    config = folder / 'client.json'
    write_json(config, client_config(exported))
    # These panel exports contain real endpoints. Existing customized clients
    # expose this switch to skip provider-specific reversible port/UUID mapping.
    client_env = dict(os.environ, **{'xray.endpoint.mapping': 'off'})
    p = launch([core, 'run', '-c', config], folder, folder / 'client.log', client_env)
    try:
        require(wait_port(CLIENT_SOCKS, 8), 'client failed to listen')
        http_probe(CLIENT_SOCKS, large=case.get('large', False))
        result(phase + '.inbound.http.' + case['name'], True)
        if case.get('udp', True):
            try:
                udp_probe(CLIENT_UDP)
                result(phase + '.inbound.udp.' + case['name'], True)
            except Exception as e:
                result(phase + '.inbound.udp.' + case['name'], False, e)
    except Exception as e:
        result(phase + '.inbound.http.' + case['name'], False, e)
    finally:
        stop(p)
        time.sleep(.05)


def current_core_pid(panel):
    children = set()
    for thread_children in Path(f'/proc/{panel.p.pid}/task').glob('*/children'):
        try:
            children.update(thread_children.read_text().split())
        except FileNotFoundError:
            pass
    for child in children:
        try:
            command = Path(f'/proc/{child}/cmdline').read_bytes().split(b'\0')
            if any(b'xray-linux-' in arg for arg in command):
                return int(child)
        except FileNotFoundError:
            continue
    raise AssertionError('panel has no live child core process')


def malformed_isolation(panel, cases, exports):
    control = next((c for c in cases if c['name'] == 'vless-stock'), None)
    core_pid = current_core_pid(panel)
    seen = set()
    for case in cases:
        protocol = case['protocol']
        if protocol not in ('anytls', 'mieru', 'dnstt', 'orbit', 'shadowtls', 'openvpn') or protocol in seen:
            continue
        seen.add(protocol)
        is_udp = protocol == 'dnstt' or case['settings'].get('network') == 'udp' or case['settings'].get('transport') in ('udp', 'quic')
        if is_udp:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b'\x00\x01malformed-e2e', ('127.0.0.1', case['port']))
        else:
            with socket.create_connection(('127.0.0.1', case['port']), timeout=2) as sock:
                sock.sendall(b'\x00\x02\x00\x00bad-handshake-e2e')
        time.sleep(.15)
        require(current_core_pid(panel) == core_pid, protocol + ' malformed input restarted or killed core')
        os.kill(core_pid, 0)
        if control:
            http_probe(control['out_socks'])
        result('malformed-isolation.' + protocol, True, 'same core PID; stock control traffic preserved' if control else 'same core PID')


def expect_denied(core, exported, folder, label):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'client.json'
    write_json(path, client_config(exported))
    p = launch([core, 'run', '-c', path], folder, folder / 'client.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        require(wait_port(CLIENT_SOCKS, 8), 'negative client configuration failed to start')
        denied = False
        try:
            http_probe(CLIENT_SOCKS, timeout=4)
        except AssertionError:
            denied = True
        require(denied, 'revoked credentials still forwarded traffic')
        result(label, True)
    finally:
        stop(p)


def apply_outbound_template(panel, cases, exports):
    template = outbound_template(cases, exports)
    panel.api('POST', '/panel/xray/update', data={'xraySetting': json.dumps(template), 'outboundTestUrl': f'http://{TARGET}:{HTTP_PORT}/echo'})
    panel.restart()
    require(wait_port(next(c['out_socks'] for c in cases if c['name'] in exports), 10), 'template reload did not start native outbound SOCKS listeners')
    saved = json.loads(panel.api('POST', '/panel/xray/'))['xraySetting']
    require(saved == template, 'template API did not preserve native outbound JSON')
    return template


def encrypted_user_routing(panel, cases, exports, core, work):
    case = next((c for c in cases if c['name'] == 'shadowtls-ss2022'), None)
    if case is None or case['name'] not in exports:
        return
    row = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
    template = outbound_template(cases, exports)
    template['routing']['rules'].insert(1, {'type': 'field', 'inboundTag': [row['tag']],
                                            'user': [case['settings']['clients'][0]['email']],
                                            'port': str(HTTP_PORT), 'outboundTag': 'blocked'})
    panel.api('POST', '/panel/xray/update', data={'xraySetting': json.dumps(template)})
    panel.restart()
    expect_denied(core, exports[case['name']], work / 'ss2022-denied-user', 'ss2022-selected-user-routing-denies-first')
    traffic_client(core, case['secondary_export'], case, work / 'ss2022-allowed-user', 'second-user-route')
    apply_outbound_template(panel, cases, exports)


def account_lifecycle(panel, cases, exports, core, work):
    preferred = {'anytls': 'anytls-normal', 'mieru': 'mieru-tcp', 'dnstt': 'dnstt-vless', 'orbit': 'orbit-tcp',
                 'shadowtls': 'shadowtls-v3', 'openvpn': 'openvpn-tcp-proof'}
    control = next((c for c in cases if c['name'] == 'vless-stock'), None)
    for protocol, name in preferred.items():
        case = next((c for c in cases if c['name'] == name), None)
        if case is None or name not in exports:
            continue
        row = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
        settings = json.loads(row['settings'])
        user = copy.deepcopy(settings['clients'][0])
        token = 'email:' + base64.urlsafe_b64encode(user['email'].encode()).decode().rstrip('=')
        def update(changed):
            panel.api('POST', '/panel/api/inbounds/updateClient/' + token,
                      json={'id': case['id'], 'settings': json.dumps({'clients': [changed]})})
            panel.restart()  # Supports native hot API updates and documented full-config fallback.
        old_export = copy.deepcopy(exports[name])
        update(dict(user, enable=False))
        expect_denied(core, old_export, work / 'revoke' / name, 'account-revoked-denied.' + protocol)
        if control:
            http_probe(control['out_socks'])
        replacement = dict(user, enable=True)
        if protocol in ('anytls', 'mieru', 'shadowtls'):
            replacement['password'] = 'rotated-' + secrets.token_hex(16)
        elif protocol == 'dnstt':
            replacement['id'] = str(uuid.uuid4())
        elif protocol == 'orbit':
            replacement['key'] = panel.api('POST', '/panel/api/server/native/credentials',
                                          json={'kind': 'orbit', 'certificate': '\n'.join(settings['tls']['certificate'])})['key']
        elif protocol == 'openvpn':
            replacement['clientProof'] = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'openvpn-proof'})
        update(replacement)
        expect_denied(core, old_export, work / 'old-credential' / name, 'account-old-credentials-denied.' + protocol)
        exports[name] = panel.export(case['subid'])
        apply_outbound_template(panel, cases, exports)
        traffic_client(core, exports[name], case, work / 'readded' / name, 'readded')
        http_probe(case['out_socks'])
        if control:
            http_probe(control['out_socks'])
        result('account-readded-outbound.' + protocol, True)


def outbound_template(cases, exports):
    template = base_template()
    for index, case in enumerate(cases):
        if case['name'] not in exports:
            continue
        name = case['name']
        cfg = client_config(exports[name], 30000 + index, 31000 + index)
        tag_map = {o['tag']: name + '-' + o['tag'] for o in cfg['outbounds']}
        for o in cfg['outbounds']:
            o['tag'] = tag_map[o['tag']]
            if 'proxySettings' in o:
                o['proxySettings']['tag'] = tag_map[o['proxySettings']['tag']]
            template['outbounds'].append(o)
        tags = []
        for inbound in cfg['inbounds']:
            inbound['tag'] = name + '-' + inbound['tag']
            tags.append(inbound['tag'])
            template['inbounds'].append(inbound)
        template['routing']['rules'].append({'type': 'field', 'inboundTag': tags, 'outboundTag': tag_map['proxy']})
        case['out_socks'] = 30000 + index
        case['out_udp'] = 31000 + index
    return template


def traffic_outbounds(cases, exports, phase):
    for case in cases:
        if case['name'] not in exports:
            continue
        try:
            http_probe(case['out_socks'], large=case.get('large', False))
            result(phase + '.outbound.http.' + case['name'], True)
        except Exception as e:
            result(phase + '.outbound.http.' + case['name'], False, e)
        if case.get('udp', True):
            try:
                udp_probe(case['out_udp'])
                result(phase + '.outbound.udp.' + case['name'], True)
            except Exception as e:
                result(phase + '.outbound.udp.' + case['name'], False, e)


def main(args):
    global cert_server_secret, WORK_CREATED
    require(os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net') != os.environ['D11_HOST_NETNS'],
            'must run inside private network namespace wrapper')
    args.panel = args.panel.resolve()
    args.core = args.core.resolve()
    if args.client_core:
        args.client_core = args.client_core.resolve()
    work = args.work.resolve()
    args.work = work
    require(not work.exists(), 'work directory must be fresh')
    work.mkdir(parents=True, mode=0o700)
    WORK_CREATED = True
    cert = certificates(work / 'fixtures')
    cert_server_secret = cert['server.key'].splitlines()[1]
    targets, udp = start_targets(work / 'fixtures')
    panel = Panel(work / 'panel-original', args.panel.resolve(), args.core.resolve(), args.panel_arch)
    panel.init()
    panel.start()
    result('isolated-panel-login', True)
    cases = make_cases(panel, cert, panel.db / 'certs')
    if args.only:
        allowed = set(args.only.split(','))
        cases = [c for c in cases if c['name'] in allowed or c['protocol'] in allowed]
    exports = configure_cases(panel, cases, work)
    for case in cases:
        if case['name'] in exports:
            traffic_client(args.client_core or args.core, exports[case['name']], case, work / 'before' / case['name'], 'before')
    apply_outbound_template(panel, cases, exports)
    result('template-outbound-roundtrip', True)
    traffic_outbounds(cases, exports, 'before')
    if args.isolation_lifecycle:
        encrypted_user_routing(panel, cases, exports, args.client_core or args.core, work)
        malformed_isolation(panel, cases, exports)
        account_lifecycle(panel, cases, exports, args.client_core or args.core, work)
    response = panel.http.get(panel.url + '/panel/api/server/getDb', timeout=45)
    response.raise_for_status()
    require(response.content[:2] == b'PK', 'backup endpoint did not return ZIP')
    backup_path = work / 'portable-backup.zip'
    backup_path.write_bytes(response.content)
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        names = z.namelist()
        require(not any(c['protocol'] == 'anytls' for c in cases) or any('asset' in name for name in names), 'file-backed TLS assets missing in backup')
        result('backup-portable-assets', True, f'{len(names)} archive members')
    # Malformed bundle rejection must leave the running original intact.
    with zipfile.ZipFile(io.BytesIO(response.content)) as original:
        broken = io.BytesIO()
        asset_name = next((n for n in original.namelist() if n.startswith('assets/')), 'database.db')
        with zipfile.ZipFile(broken, 'w') as altered:
            for name in original.namelist():
                if name != asset_name:
                    altered.writestr(name, original.read(name))
    rejection = panel.http.post(panel.url + '/panel/api/server/importDB',
                                files={'db': ('missing-asset.zip', broken.getvalue(), 'application/zip')}, timeout=60)
    require(rejection.status_code == 200 and not rejection.json().get('success'), 'missing asset backup was accepted')
    panel.api('GET', '/panel/api/inbounds/list')
    survivor = next(c for c in cases if c['name'] in exports)
    http_probe(survivor['out_socks'])
    result('restore-rejects-missing-asset-keeps-service', True)
    stop(panel.p)
    panel.p = None
    # Prove the restored panel does not depend on the old file paths.
    shutil.rmtree(panel.db / 'certs')
    panel2 = Panel(work / 'panel-restored', args.panel.resolve(), args.core.resolve(), args.panel_arch)
    panel2.init()
    panel2.start()
    with backup_path.open('rb') as f:
        restore_reply = panel2.api('POST', '/panel/api/server/importDB', files={'db': ('backup.zip', f, 'application/zip')})
    if args.expect_reload:
        wait_restore_reload(panel2, restore_reply, 'restore-auto-reload')
    else:
        panel2.login()
    restored = panel2.api('GET', '/panel/api/inbounds/list')
    require(len(restored) == len(cases), 'restored inbound count mismatch')
    result('restore-fresh-db', True, f'{len(restored)} inbounds')
    refs = []
    for row in restored:
        if row['protocol'] == 'anytls':
            c = json.loads(row['streamSettings'])['tlsSettings']['certificates'][0]
            for key in ('certificateFile', 'keyFile'):
                path = Path(c[key]); refs.append(str(path))
                require(path.exists() and str(panel2.db) in str(path), 'restored asset path missing or not remapped')
                require(path.stat().st_mode & 0o777 == 0o600, 'restored asset mode not 0600')
    result('restore-assets-remapped-private', True, f'{len(refs)} certificate references')
    for case in cases:
        if case['name'] in exports:
            exported = panel2.export(case['subid'])
            require(exported['outbounds'] == exports[case['name']]['outbounds'], 'export changed across backup restore: ' + case['name'])
            traffic_client(args.client_core or args.core, exported, case, work / 'after' / case['name'], 'after')
    traffic_outbounds(cases, exports, 'after')
    if args.expect_reload:
        stopped_listener_restore(panel2, cases, exports)
    stop(panel2.p)
    for srv in targets:
        srv.shutdown()
    udp.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--panel', type=Path, required=True)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--panel-arch', choices=['amd64', 'arm64'], default='amd64', help='select bundled core filename; wrappers can execute QEMU explicitly')
    parser.add_argument('--client-core', type=Path, help='optional reference client binary; server always uses --core')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--isolation-lifecycle', action='store_true', help='bounded malformed native traffic and revoke/replace credentials through real client APIs')
    parser.add_argument('--expect-reload', action='store_true', help='require automatic panel/sub reload and test changed listeners/manual-stop preservation')
    parser.add_argument('--only', help='comma-separated case names/protocols for debugging; omitted for full suite')
    args = parser.parse_args()
    os.umask(0o077)
    completed = False
    try:
        main(args)
        completed = True
    except KeyboardInterrupt:
        result('harness-completion', False, 'interrupted before suite completed')
    except Exception as e:
        result('harness-completion', False, e)
        traceback.print_exc()
    finally:
        for p in reversed(PROCESSES):
            stop(p)
        if WORK_CREATED:
            write_json(args.work / 'results.json', {'completed': completed, 'passed': sum(r['ok'] for r in RESULTS), 'failed': sum(not r['ok'] for r in RESULTS),
                                                  'network': 'private namespace; loopback only', 'panel_binary': str(args.panel), 'core_binary': str(args.core), 'reference_client': str(args.client_core) if args.client_core else None, 'reference_endpoint_mapping': 'off (raw synthetic panel endpoints)', 'results': RESULTS})
            print('RESULTS ' + str(args.work / 'results.json'), flush=True)
        else:
            print('No artifacts written: work directory was not created by this run.', flush=True)
    sys.exit(1 if not completed or any(not r['ok'] for r in RESULTS) else 0)
