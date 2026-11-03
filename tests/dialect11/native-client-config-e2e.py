#!/usr/bin/env python3
"""Selected-client full JSON -> unchanged custom client -> local TCP/SOCKS UDP.

Run with --netns. Only disposable panel databases and loopback/benchmark targets
inside that private network namespace are used. Returned configurations are
written, parsed and run unchanged; no listener, routing or outbound repairs.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.umask(0o077)
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('default_profiles', HERE / 'default-profiles-e2e.py')
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)
h = d.h
SOCKS_PORT = 10808


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configuration_hash(panel):
    # Runtime statistics may change independently; the request must not change
    # any saved inbound/client material or panel setting.
    with sqlite3.connect(panel.db / 'x-ui.db') as database:
        saved = {
            'inbounds': database.execute('SELECT * FROM inbounds ORDER BY id').fetchall(),
            'settings': database.execute('SELECT * FROM settings ORDER BY id').fetchall(),
        }
    return hashlib.sha256(json.dumps(saved, sort_keys=True).encode()).hexdigest()


def recv_exact(connection, count):
    result = b''
    while len(result) < count:
        block = connection.recv(count - len(result))
        h.require(block, 'SOCKS control connection ended early')
        result += block
    return result


def socks_address(connection, kind):
    if kind == 1:
        return socket.inet_ntop(socket.AF_INET, recv_exact(connection, 4))
    if kind == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(connection, 16))
    if kind == 3:
        return recv_exact(connection, recv_exact(connection, 1)[0]).decode('ascii')
    raise AssertionError('unsupported SOCKS address type')


def socks_udp_probe(timeout=8):
    """Use the actual copied SOCKS UDP inbound, without adding a test inbound."""
    payload = b'native-full-json-udp-' + os.urandom(256)
    with socket.create_connection(('127.0.0.1', SOCKS_PORT), timeout=timeout) as control:
        control.settimeout(timeout)
        control.sendall(b'\x05\x01\x00')
        h.require(recv_exact(control, 2) == b'\x05\x00', 'SOCKS noauth negotiation failed')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        header = recv_exact(control, 4)
        h.require(header[:3] == b'\x05\x00\x00', 'SOCKS UDP association rejected')
        address = socks_address(control, header[3])
        port = struct.unpack('!H', recv_exact(control, 2))[0]
        if address in ('0.0.0.0', '::'):
            address = '127.0.0.1'
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            frame = b'\x00\x00\x00\x01' + socket.inet_aton(h.TARGET) + struct.pack('!H', h.UDP_PORT) + payload
            udp.sendto(frame, (address, port))
            response, _ = udp.recvfrom(4096)
            h.require(response[:3] == b'\x00\x00\x00', 'invalid or fragmented SOCKS UDP response')
            kind = response[3]
            offset = 8 if kind == 1 else 20 if kind == 4 else 5 + response[4] if kind == 3 else -1
            h.require(offset > 0 and len(response) >= offset + 2, 'invalid SOCKS UDP response address')
            h.require(response[offset + 2:] == payload, 'SOCKS UDP payload mismatch')


def settings_for_selected(panel, case):
    row = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
    case['settings'] = json.loads(row['settings'])
    users = case['settings']['clients']
    h.require(len(users) == 2, 'fixture requires two distinct accounts')
    return users[1]


def assert_selected_and_private(case, selected, config):
    d.assert_export(case, config)
    h.require(isinstance(config.get('routing'), dict), 'full config lacks routing')
    socks = [item for item in config.get('inbounds', []) if item.get('protocol') == 'socks']
    h.require(len(socks) == 1 and socks[0].get('listen') == '127.0.0.1' and socks[0].get('port') == SOCKS_PORT,
              'copy did not provide the promised complete SOCKS listener')
    h.require(socks[0].get('settings', {}).get('udp') is True, 'copied SOCKS listener lacks UDP')
    leaves = list(d.string_leaves(config))
    text = json.dumps(config)
    protocol = case['protocol']
    proxy = next(item for item in config['outbounds'] if item['tag'] == 'proxy')
    settings = proxy['settings']
    if protocol == 'orbit':
        h.require(settings.get('key') == selected['key'], 'copied wrong Orbit client')
    elif protocol == 'dnstt':
        h.require(settings['tunnel']['inner'].get('uuid') == selected['id'], 'copied wrong DNSTT client')
    elif protocol == 'openvpn':
        certs = settings['certificates']
        h.require(certs.get('key') == selected['privateKey'], 'copied wrong OpenVPN private key')
        h.require(certs.get('cert') == selected['certificate'], 'copied wrong OpenVPN certificate')
        h.require(certs.get('tlsCryptV2') == selected['tlsCryptV2'], 'copied wrong OpenVPN control key')
    elif protocol == 'shadowtls':
        carrier = next(item for item in config['outbounds'] if item['protocol'] == 'shadowtls')
        h.require(carrier['settings'].get('password') == selected['password'], 'copied wrong ShadowTLS account')
        inner = case['settings']['inner']['settings']
        inner_selected = next(item for item in inner['clients'] if item['email'] == selected['email'])
        expected = inner['password'] + ':' + inner_selected['password']
        h.require(settings['servers'][0]['password'] == expected, 'copied wrong ShadowTLS inner identity')
        for account in inner['clients']:
            if account['email'] != selected['email']:
                h.require(account['password'] not in text, 'other ShadowTLS inner client leaked')
    else:
        h.require(settings.get('password') == selected['password'], 'copied wrong native password')
        if protocol == 'mieru':
            h.require(settings.get('username') == selected['username'], 'copied wrong Mieru username')
    for user in case['settings']['clients']:
        if user['email'] == selected['email']:
            continue
        for field in ('password', 'key', 'id', 'privateKey', 'tlsCryptV2', 'subId'):
            value = user.get(field)
            if isinstance(value, str) and len(value) >= 12:
                if '\n' not in value:
                    h.require(not any(value in leaf for leaf in leaves), 'another client credential leaked: ' + field)
                    continue
                # Check PEM payload lines too, regardless of string/array form.
                for secret in value.splitlines():
                    if len(secret) >= 32 and not secret.startswith('-----'):
                        h.require(not any(secret in leaf for leaf in leaves), 'another client credential leaked: ' + field)
    for field in ('issuerPrivateKey', 'certificateFile', 'keyFile'):
        h.require('"' + field + '"' not in text, 'server-only material/reference leaked: ' + field)


def disable_subscriptions(panel, cases):
    for case in cases:
        selected = settings_for_selected(panel, case)
        updated = dict(selected, subId='')
        token = 'email:' + base64.urlsafe_b64encode(selected['email'].encode()).decode().rstrip('=')
        panel.api('POST', '/panel/api/inbounds/updateClient/' + token, json={
            'id': case['id'], 'settings': json.dumps({'clients': [updated]})})
        h.require(settings_for_selected(panel, case).get('subId', '') == '', 'fixture could not clear selected subscription ID')
    h.stop(panel.p)
    with sqlite3.connect(panel.db / 'x-ui.db') as database:
        for key in ('subEnable', 'subJsonEnable', 'subClashEnable'):
            cursor = database.execute('UPDATE settings SET value=? WHERE key=?', ('false', key))
            if cursor.rowcount == 0:
                database.execute('INSERT INTO settings(key,value) VALUES(?,?)', (key, 'false'))
        database.commit()
    panel.p = h.launch([panel.panel_bin, 'run'], panel.root, panel.logs / 'panel.log', panel.env)
    h.require(h.wait_port(h.PANEL_PORT, 20), 'panel failed to restart with subscriptions disabled')
    panel.login()
    with socket.socket() as probe:
        probe.settimeout(.3)
        h.require(probe.connect_ex(('127.0.0.1', h.SUB_PORT)) != 0, 'subscription listener still enabled')
    h.result('copy.subscription-server-off-and-selected-subids-empty', True)


def copy_response(panel, case, selected):
    route = '/panel/api/inbounds/' + str(case['id']) + '/clientConfig'
    response = panel.http.post(panel.url + route, json={'email': selected['email']},
                               headers={'X-Requested-With': 'XMLHttpRequest'}, timeout=30)
    response.raise_for_status()
    h.require(response.headers.get('Cache-Control') == 'no-store', 'copy response may be cached')
    body = response.json()
    h.require(body.get('success'), body.get('msg', 'copy rejected'))
    obj = body.get('obj', {})
    h.require(isinstance(obj.get('config'), dict), 'copy response is not a JSON config object')
    h.require(isinstance(obj.get('filename'), str) and re.fullmatch(r'[A-Za-z0-9._-]+\.json', obj['filename']),
              'unsafe copy filename')
    return obj['config']


def test_rejections(panel, cases):
    first = cases[0]
    route = '/panel/api/inbounds/' + str(first['id']) + '/clientConfig'
    selected = settings_for_selected(panel, first)
    anonymous = h.requests.Session()
    anonymous.trust_env = False
    response = anonymous.post(panel.url + route, json={'email': selected['email']}, timeout=10, allow_redirects=False)
    h.require(response.status_code in (301, 302, 303, 401, 403, 404), 'unauthenticated copy was accepted')
    h.require(selected.get('key', 'missing-key-marker') not in response.text, 'anonymous copy leaked credentials')
    anonymous.close()
    h.result('copy.unauthenticated-rejected', True)
    foreign = settings_for_selected(panel, cases[1])['email']
    for name, payload in [('foreign-inbound-client', {'email': foreign}), ('missing-client', {'email': 'absent@example.test'})]:
        response = panel.http.post(panel.url + route, json=payload, timeout=10)
        h.require(not response.json().get('success') and not response.json().get('obj'), 'invalid client copy returned configuration')
        h.result('copy.' + name + '-rejected', True)


def exact_client_traffic(panel, client_core, case, path, work):
    expected_hash = file_hash(path)
    env = dict(os.environ, **{'xray.endpoint.mapping': 'off'})
    folder = work / 'traffic' / case['protocol']
    folder.mkdir(parents=True)
    p = h.launch([client_core, 'run', '-c', path], folder, folder / 'positive.log', env)
    try:
        h.require(h.wait_port(SOCKS_PORT, 12), 'copied config failed to start SOCKS listener')
        h.http_probe(SOCKS_PORT, large=True, timeout=35)
        h.result('copy.exact-json.http-large.' + case['protocol'], True)
        socks_udp_probe()
        h.result('copy.exact-json.socks-udp.' + case['protocol'], True)
    finally:
        h.stop(p)
    # Reuse the very same JSON with the isolated server stopped. An accidental
    # direct route would still reach the local target, so it must fail here.
    panel.api('POST', '/panel/api/server/stopXrayService')
    p = h.launch([client_core, 'run', '-c', path], folder, folder / 'server-stopped.log', env)
    try:
        h.require(h.wait_port(SOCKS_PORT, 12), 'negative run did not start copied SOCKS listener')
        denied = False
        try:
            h.http_probe(SOCKS_PORT, timeout=3)
        except AssertionError:
            denied = True
        h.require(denied, 'copied config bypassed its stopped native server')
        h.result('copy.no-direct-bypass.' + case['protocol'], True)
        udp_denied = False
        try:
            socks_udp_probe(timeout=3)
        except (AssertionError, OSError):
            udp_denied = True
        h.require(udp_denied, 'copied config sent UDP directly with its native server stopped')
        h.result('copy.no-direct-udp-bypass.' + case['protocol'], True)
    finally:
        h.stop(p)
        panel.restart()
    h.require(file_hash(path) == expected_hash, 'test changed copied JSON')


def main(args):
    h.require(os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net') != os.environ['D11_HOST_NETNS'],
              'private network namespace is required')
    work = args.work.resolve()
    h.require(not work.exists(), 'work directory must be new')
    work.mkdir(parents=True, mode=0o700)
    panel = None
    targets, udp = [], None
    complete = False
    subscription_disabled = False
    copied = []
    def interrupted(signum, _frame):
        # Detached test children outlive SIGTERM by default. Unwind through
        # finally so cancelling this harness cannot strand its private panel.
        signal.signal(signum, signal.SIG_IGN)
        raise InterruptedError('integration test interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        h.certificates(work / 'fixtures')
        os.environ['SSL_CERT_FILE'] = str(work / 'fixtures' / 'ca.crt')
        targets, udp = h.start_targets(work / 'fixtures')
        panel = h.Panel(work / 'panel', args.panel.resolve(), args.core.resolve(), arch=args.panel_arch)
        panel.init()
        panel.start()
        cases = d.generate_cases(panel, work)
        exports = d.configure(panel, cases, work)
        d.add_generated_clients(panel, cases, exports, work)
        disable_subscriptions(panel, cases)
        subscription_disabled = True
        before = configuration_hash(panel)
        server_pid = h.current_core_pid(panel)
        test_rejections(panel, cases)
        for case in cases:
            selected = settings_for_selected(panel, case)
            config = copy_response(panel, case, selected)
            assert_selected_and_private(case, selected, config)
            path = work / (case['protocol'] + '-copied.json')
            h.write_json(path, config)
            h.result('copy.selected-account-and-private-material.' + case['protocol'], True)
            check = subprocess.run([str(args.client_core.resolve()), 'run', '-test', '-c', str(path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   timeout=30, env=dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
            path.with_suffix('.parse.log').write_text(check.stdout)
            h.require(check.returncode == 0, 'unchanged custom client rejected full JSON: ' + check.stdout[-600:])
            h.result('copy.exact-json.custom25-parser.' + case['protocol'], True)
            copied.append((case, path))
        h.require(configuration_hash(panel) == before, 'copy route changed saved inbounds or settings')
        h.result('copy.no-saved-configuration-mutation', True)
        h.require(h.current_core_pid(panel) == server_pid, 'copy route replaced the running server core')
        h.result('copy.running-server-core-preserved', True)
        for case, path in copied:
            exact_client_traffic(panel, args.client_core.resolve(), case, path, work)
        complete = True
    except Exception as error:
        h.result('copy.integration-completion', False, str(error))
        (work / 'failure.txt').write_text(traceback.format_exc())
    finally:
        if panel:
            h.stop(panel.p)
        for process in reversed(h.PROCESSES):
            h.stop(process)
        for target in targets:
            target.shutdown()
        if udp:
            udp.close()
        namespace = os.readlink('/proc/self/ns/net')
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            try:
                if os.readlink(proc / 'ns/net') == namespace:
                    os.kill(int(proc.name), signal.SIGTERM)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        report = {
            'complete': complete, 'passed': sum(item['ok'] for item in h.RESULTS),
            'failed': sum(not item['ok'] for item in h.RESULTS), 'responseConfigRepaired': False,
            'panelArchitecture': args.panel_arch,
            'subscriptionServingDisabled': subscription_disabled, 'testedCopiedConfigs': len(copied),
            'parsedCopiedConfigs': len(copied),
            'trafficVerifiedConfigs': sum(item['ok'] and item['name'].startswith('copy.no-direct-udp-bypass.')
                                         for item in h.RESULTS),
            'binaries': {name: {'path': str(path.resolve()), 'sha256': file_hash(path)} for name, path in (
                ('panel', args.panel), ('serverCore', args.core), ('unchangedCustom25Client', args.client_core))},
            'results': h.RESULTS,
        }
        h.write_json(work / 'results.json', report)
        print('RESULTS ' + str(work / 'results.json'), flush=True)
    return 0 if complete and all(item['ok'] for item in h.RESULTS) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('panel', 'core', 'client-core', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--panel-arch', choices=('amd64', 'arm64'), default='amd64')
    parser.add_argument('--netns', action='store_true')
    arguments = parser.parse_args()
    if arguments.netns:
        os.environ['D11_HOST_NETNS'] = os.readlink('/proc/self/ns/net')
        os.execvp('unshare', ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                             *[arg for arg in sys.argv[1:] if arg != '--netns']])
    h.require(os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net') != os.environ['D11_HOST_NETNS'],
              'invoke with --netns')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'address', 'add', '198.18.0.1/32', 'dev', 'lo'], check=True)
    raise SystemExit(main(arguments))
