#!/usr/bin/env python3
"""Controlled VLESS/Trojan TLS regression for a bundled server-core candidate.

No production database or service is used. Run with --netns. The harness creates
legacy inbounds through the real disposable panel API, then runs the official
stock client before the immutable custom client. Client JSON is a local fixture,
not a native-protocol export. All credentials and detailed logs stay private.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.umask(0o077)
SOCKS_PORT = 10808
PAYLOAD = bytes(range(256)) * 4096
RESULTS = []
METRICS = []
h = None


def load_helpers(repo):
    global h
    spec = importlib.util.spec_from_file_location('legacy_tls_panel_helpers', repo / 'tests/dialect11/panel-e2e.py')
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def record(name, ok, detail=''):
    RESULTS.append({'name': name, 'ok': bool(ok), 'detail': detail})
    print(('PASS ' if ok else 'FAIL ') + name + (': ' + detail if detail else ''), flush=True)


def check(name, function, folder):
    try:
        value = function()
        record(name, True)
        return value
    except Exception as error:
        # The machine-readable result contains no raw upstream messages or
        # configuration material. Full diagnostic traces remain private.
        record(name, False, type(error).__name__)
        with (folder / 'failures.log').open('a') as target:
            target.write(name + '\n' + traceback.format_exc() + '\n')
        return None


def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        block = connection.recv(length - len(data))
        if not block:
            raise AssertionError('connection ended early')
        data.extend(block)
    return bytes(data)


def socks_connection(timeout):
    connection = socket.create_connection(('127.0.0.1', SOCKS_PORT), timeout=timeout)
    try:
        connection.settimeout(timeout)
        connection.sendall(b'\x05\x01\x00')
        h.require(exact(connection, 2) == b'\x05\x00', 'SOCKS authentication rejected')
        connection.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(h.TARGET) + struct.pack('!H', h.HTTP_PORT))
        header = exact(connection, 4)
        h.require(header[:3] == b'\x05\x00\x00', 'SOCKS connection rejected')
        if header[3] == 1:
            exact(connection, 4)
        elif header[3] == 4:
            exact(connection, 16)
        elif header[3] == 3:
            exact(connection, exact(connection, 1)[0])
        else:
            raise AssertionError('unknown SOCKS address type')
        exact(connection, 2)
        return connection
    except Exception:
        connection.close()
        raise


class HTTPFixture(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(PAYLOAD)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 4 * len(PAYLOAD):
            self.send_error(413)
            return
        body = self.rfile.read(length)
        self.reply(json.dumps({'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}).encode())

    def log_message(self, *_):
        pass


def request(method='GET', body=None, timeout=12):
    start = time.monotonic()
    connection = http.client.HTTPConnection(h.TARGET, h.HTTP_PORT, timeout=timeout)
    connection.sock = socks_connection(timeout)
    try:
        connection.request(method, '/', body=body)
        response = connection.getresponse()
        result = response.read()
        h.require(response.status == 200, 'unexpected fixture status')
        return result, time.monotonic() - start
    finally:
        connection.close()


def traffic(label, folder):
    def download():
        body, elapsed = request()
        h.require(body == PAYLOAD, 'download integrity mismatch')
        METRICS.append({'case': label, 'check': 'download', 'bytes': len(body), 'seconds': round(elapsed, 6),
                        'sha256Verified': True})
    def upload():
        body, elapsed = request('POST', PAYLOAD)
        answer = json.loads(body)
        h.require(answer == {'bytes': len(PAYLOAD), 'sha256': hashlib.sha256(PAYLOAD).hexdigest()}, 'upload integrity mismatch')
        METRICS.append({'case': label, 'check': 'upload', 'bytes': len(PAYLOAD), 'seconds': round(elapsed, 6),
                        'sha256Verified': True})
    check(label + '.download', download, folder)
    check(label + '.upload', upload, folder)


def client_config(protocol, port, credential, ca, version):
    if protocol == 'vless':
        settings = {'vnext': [{'address': '127.0.0.1', 'port': port,
                              'users': [{'id': credential, 'encryption': 'none'}]}]}
    else:
        settings = {'servers': [{'address': '127.0.0.1', 'port': port, 'password': credential}]}
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': SOCKS_PORT, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'tag': 'proxy', 'protocol': protocol, 'settings': settings,
                           'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                               'serverName': 'e2e.test', 'allowInsecure': False, 'disableSystemRoot': True,
                               'minVersion': version, 'maxVersion': version, 'enableSessionResumption': False,
                               'certificates': [{'certificate': ca.splitlines(), 'usage': 'verify'}]}}}],
            'routing': {'domainStrategy': 'AsIs', 'rules': []}}


def parse(core, path, log):
    result = subprocess.run([str(core), 'run', '-test', '-c', str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=30)
    log.write_text(result.stdout)
    h.require(result.returncode == 0, 'client fixture parser rejected configuration')


def launch_client(core, path, folder, label):
    process = h.launch([core, 'run', '-c', path], folder, folder / (label + '.log'),
                       dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        h.require(h.wait_port(SOCKS_PORT, 10), 'client SOCKS listener did not start')
        return process
    except Exception:
        h.stop(process)
        raise


def exercise_client(core, role, config, folder, case_name):
    label = case_name + '.' + role
    path = folder / (role + '.json')
    h.write_json(path, config)
    checksum = digest(path)
    process = None
    try:
        parse(core, path, folder / (role + '-parse.log'))
        record(label + '.parse', True)
        process = launch_client(core, path, folder, role)
        traffic(label, folder)
        h.require(digest(path) == checksum, 'client fixture changed while running')
        record(label + '.config-unchanged', True)
    except Exception as error:
        record(label + '.start', False, type(error).__name__)
        (folder / (role + '-start-failure.log')).write_text(traceback.format_exc())
    finally:
        h.stop(process)
    bad = copy.deepcopy(config)
    settings = bad['outbounds'][0]['settings']
    if bad['outbounds'][0]['protocol'] == 'vless':
        settings['vnext'][0]['users'][0]['id'] = str(uuid.uuid4())
    else:
        settings['servers'][0]['password'] = uuid.uuid4().hex
    bad_path = folder / (role + '-wrong-auth.json')
    h.write_json(bad_path, bad)
    process = None
    try:
        parse(core, bad_path, folder / (role + '-wrong-auth-parse.log'))
        process = launch_client(core, bad_path, folder, role + '-wrong-auth')
        denied = False
        try:
            request(timeout=4)
        except (OSError, AssertionError, http.client.HTTPException):
            denied = True
        h.require(denied, 'wrong credentials forwarded traffic')
        record(label + '.wrong-auth-denied', True)
    except Exception as error:
        record(label + '.wrong-auth-denied', False, type(error).__name__)
        (folder / (role + '-wrong-auth-failure.log')).write_text(traceback.format_exc())
    finally:
        h.stop(process)


def atomic_write(path, data):
    temporary = path.with_name(path.name + '.replacement')
    temporary.write_bytes(data)
    os.replace(temporary, path)


def pem_der_digest(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()


def peer_certificate(port, ca_path, version, name='e2e.test'):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2 if version == '1.2' else ssl.TLSVersion.TLSv1_3
    context.maximum_version = context.minimum_version
    with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
        with context.wrap_socket(raw, server_hostname=name) as secured:
            h.require(secured.version() == 'TLSv' + version, 'TLS version negotiation changed')
            return hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()


def wait_certificate(port, fixtures, version, expected):
    deadline = time.monotonic() + 10
    while True:
        try:
            actual = peer_certificate(port, fixtures / 'ca.crt', version)
            if actual == expected:
                return
        except (OSError, AssertionError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError('certificate cache did not publish expected renewal')
        time.sleep(.2)


def generate_renewals(fixtures):
    # First renewal deliberately retains the same private key, allowing an
    # atomic leaf-only replacement. A separate pair tests mismatched-key safety.
    h.openssl(fixtures, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
              '-set_serial', '2002', '-days', '2', '-extfile', 'server.ext', '-out', 'server-renewed.crt')
    h.openssl(fixtures, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
              '-subj', '/CN=server-rotated', '-keyout', 'server-rotated.key', '-out', 'server-rotated.csr')
    h.openssl(fixtures, 'x509', '-req', '-in', 'server-rotated.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
              '-set_serial', '2003', '-days', '2', '-extfile', 'server.ext', '-out', 'server-rotated.crt')


def reload_checks(panel, case, fixtures, folder, config, client_core):
    label = case['name'] + '.reload'
    tls_certificate = case['stream']['tlsSettings']['certificates'][0]
    certificate_path, key_path = Path(tls_certificate['certificateFile']), Path(tls_certificate['keyFile'])
    pid = h.current_core_pid(panel)
    previous = pem_der_digest(fixtures / 'server.crt')
    renewed = pem_der_digest(fixtures / 'server-renewed.crt')
    rotated = pem_der_digest(fixtures / 'server-rotated.crt')
    wait_certificate(case['port'], fixtures, case['tlsVersion'], previous)
    atomic_write(certificate_path, (fixtures / 'server-renewed.crt').read_bytes())
    wait_certificate(case['port'], fixtures, case['tlsVersion'], renewed)
    record(label + '.valid-renewal-published', True)
    atomic_write(certificate_path, b'-----BEGIN CERTIFICATE-----\ninvalid-test-material\n-----END CERTIFICATE-----\n')
    time.sleep(2.2)
    h.require(peer_certificate(case['port'], fixtures / 'ca.crt', case['tlsVersion']) == renewed,
              'malformed replacement discarded working certificate')
    record(label + '.malformed-retains-last-good', True)
    atomic_write(certificate_path, (fixtures / 'server-rotated.crt').read_bytes())
    time.sleep(2.2)
    h.require(peer_certificate(case['port'], fixtures / 'ca.crt', case['tlsVersion']) == renewed,
              'mismatched key replacement discarded working certificate')
    record(label + '.mismatched-key-retains-last-good', True)
    atomic_write(key_path, (fixtures / 'server-rotated.key').read_bytes())
    wait_certificate(case['port'], fixtures, case['tlsVersion'], rotated)
    record(label + '.valid-pair-recovers', True)
    h.require(h.current_core_pid(panel) == pid, 'file reload restarted the core')
    record(label + '.same-core-process', True)
    path = folder / 'custom-after-reload.json'
    h.write_json(path, config)
    process = launch_client(client_core, path, folder, 'custom-after-reload')
    try:
        traffic(case['name'] + '.custom-after-reload', folder)
    finally:
        h.stop(process)


def main(args):
    load_helpers(args.repo.resolve())
    work = args.work.resolve()
    h.require(not work.exists(), 'work directory must be new')
    work.mkdir(parents=True, mode=0o700)
    binaries = {name: {'path': str(getattr(args, name).resolve()), 'sha256': digest(getattr(args, name).resolve())}
                for name in ('panel', 'server_core', 'stock_core', 'client_core')}
    panel = target = None
    completed = 0
    cases = [(protocol, storage, version) for protocol in ('vless', 'trojan')
             for storage in ('inline', 'file') for version in ('1.2', '1.3')]
    try:
        fixtures = work / 'fixtures'
        certificates = h.certificates(fixtures)
        generate_renewals(fixtures)
        target = http.server.ThreadingHTTPServer((h.TARGET, h.HTTP_PORT), HTTPFixture)
        target.daemon_threads = True
        threading.Thread(target=target.serve_forever, daemon=True).start()
        panel = h.Panel(work / 'panel', args.panel.resolve(), args.server_core.resolve())
        panel.init()
        panel.start()
        for index, (protocol, storage, version) in enumerate(cases):
            name = protocol + '-' + storage + '-tls' + version.replace('.', '')
            folder = work / 'cases' / name
            folder.mkdir(parents=True)
            case = None
            try:
                credential = str(uuid.uuid4()) if protocol == 'vless' else uuid.uuid4().hex
                user = {'email': name + '@matrix.test', 'enable': True, 'subId': uuid.uuid4().hex,
                        'id' if protocol == 'vless' else 'password': credential}
                settings = {'clients': [user]}
                if protocol == 'vless':
                    settings['decryption'] = 'none'
                if storage == 'file':
                    atomic_write(folder / 'active.crt', (fixtures / 'server.crt').read_bytes())
                    atomic_write(folder / 'active.key', (fixtures / 'server.key').read_bytes())
                    cert = {'certificateFile': str(folder / 'active.crt'), 'keyFile': str(folder / 'active.key'),
                            'usage': 'encipherment', 'oneTimeLoading': False, 'ocspStapling': 1}
                else:
                    cert = {'certificate': certificates['server.crt'].splitlines(),
                            'key': certificates['server.key'].splitlines(), 'usage': 'encipherment'}
                case = {'name': name, 'port': 29400 + index, 'protocol': protocol, 'settings': settings,
                        'stream': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                            'minVersion': version, 'maxVersion': version, 'rejectUnknownSni': True,
                            'certificates': [cert]}}, 'tlsVersion': version}
                answer = panel.api('POST', '/panel/api/inbounds/add', json=h.payload(case))
                case['id'] = answer['id']
                stored = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
                h.require(json.loads(stored['streamSettings']) == case['stream'], 'legacy TLS settings changed on save')
                h.require(json.loads(stored['settings'])['clients'][0][
                    'id' if protocol == 'vless' else 'password'] == credential, 'saved credential changed')
                record(name + '.panel-create-persist', True)
                panel.restart()
                h.require(h.wait_port(case['port'], 15), 'legacy TLS listener did not start')
                h.require(peer_certificate(case['port'], fixtures / 'ca.crt', version) == pem_der_digest(fixtures / 'server.crt'),
                          'wrong initial trusted certificate')
                record(name + '.trusted-tls-version', True)
                denied = False
                try:
                    peer_certificate(case['port'], fixtures / 'ca.crt', version, 'wrong.example.test')
                except (ssl.SSLError, ConnectionError):
                    denied = True
                h.require(denied, 'wrong TLS identity accepted')
                record(name + '.wrong-sni-denied', True)
                config = client_config(protocol, case['port'], credential, certificates['ca.crt'], version)
                # Keep the official stock prerequisite ahead of the custom
                # client on every valid fixture, not only the first protocol.
                exercise_client(args.stock_core.resolve(), 'stock', config, folder, name)
                exercise_client(args.client_core.resolve(), 'custom', config, folder, name)
                if storage == 'file':
                    check(name + '.reload-complete', lambda: reload_checks(panel, case, fixtures, folder, config,
                                                                         args.client_core.resolve()), folder)
                completed += 1
            except Exception as error:
                record('scenario.' + name, False, type(error).__name__)
                (folder / 'failure.log').write_text(traceback.format_exc())
            finally:
                for process in reversed(h.PROCESSES):
                    if process is not panel.p:
                        h.stop(process)
                if case and case.get('id'):
                    panel.api('POST', '/panel/api/inbounds/del/' + str(case['id']))
                    panel.restart()
            h.write_json(work / 'progress.json', {'completed': completed, 'total': len(cases), 'results': RESULTS, 'metrics': METRICS})
    except Exception as error:
        record('legacy-tls.completion', False, type(error).__name__)
        (work / 'failure.log').write_text(traceback.format_exc())
    finally:
        for process in reversed(h.PROCESSES):
            h.stop(process)
        if target:
            target.shutdown()
            target.server_close()
        unchanged = all(digest(Path(value['path'])) == value['sha256'] for value in binaries.values())
        record('binaries.unchanged', unchanged)
        report = {'complete': completed == len(cases), 'completedScenarios': completed, 'totalScenarios': len(cases),
                  'passed': sum(result['ok'] for result in RESULTS), 'failed': sum(not result['ok'] for result in RESULTS),
                  'privateNetworkNamespace': True, 'defaultRoute': False, 'stockFirst': True,
                  'clientJSONOrigin': 'controlled locally constructed legacy fixture; not a native export',
                  'binaries': binaries, 'results': RESULTS, 'metrics': METRICS}
        h.write_json(work / 'results.json', report)
        print('RESULTS ' + str(work / 'results.json'), flush=True)
    return 0 if report['complete'] and not report['failed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'panel', 'server-core', 'stock-core', 'client-core', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--netns', action='store_true')
    arguments = parser.parse_args()
    if arguments.netns:
        os.environ['D11_LEGACY_HOST_NETNS'] = os.readlink('/proc/self/ns/net')
        os.execvp('unshare', ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                             *[item for item in sys.argv[1:] if item != '--netns']])
    if not os.environ.get('D11_LEGACY_HOST_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['D11_LEGACY_HOST_NETNS']:
        parser.error('invoke with --netns')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'address', 'add', '198.18.0.1/32', 'dev', 'lo'], check=True)
    if subprocess.check_output(['ip', 'route', 'show', 'default'], text=True).strip():
        parser.error('isolated fixture namespace unexpectedly has a default route')
    def interrupted(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise InterruptedError('test interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main(arguments))
