#!/usr/bin/env python3
"""Panel-generated native profiles -> untouched client -> local TCP/UDP traffic.

Invoke through run-default-profiles-e2e.sh. Imports existing panel E2E helpers;
all fixtures, processes, databases and listeners remain in a private namespace.
Only addresses/ports are adapted. ShadowTLS's controlled cover certificate is
trusted via SSL_CERT_FILE in the test environment; exported credential objects
are never replaced or repaired by this test.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import traceback
import zipfile
import uuid

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('panel_e2e', HERE / 'panel-e2e.py')
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)
PROTOCOLS = ('orbit', 'dnstt', 'openvpn', 'anytls', 'shadowtls', 'mieru')
DEPLOYMENT_INPUTS = {
    'orbit': {'serverAddress': '127.0.0.1'},
    'dnstt': {'domain': 'tunnel.example.test'},
    'openvpn': {},
    'anytls': {'serverName': 'e2e.test'},
    'shadowtls': {'handshakeAddress': '127.0.0.1'},
    'mieru': {},
}


def request_profile(panel, protocol, domain_host=False, explicit=True):
    request = {'kind': 'inbound-profile', 'protocol': protocol}
    if explicit:
        request.update(DEPLOYMENT_INPUTS[protocol])
    client, url = panel.http, panel.url
    if domain_host:
        # Authenticate the actual hostname separately: session cookies are
        # deliberately scoped to the host, so a forged Host header alone
        # would exercise the login rejection path rather than generation.
        client = h.requests.Session()
        client.trust_env = False
        url = panel.url.replace('127.0.0.1', 'localhost')
        login = client.post(url + '/login', data={'username': 'e2e-admin', 'password': 'e2e-only-private-namespace'}, timeout=10)
        login.raise_for_status()
        h.require(login.json().get('success'), 'domain-hosted panel login failed')
    try:
        response = client.post(url + '/panel/api/server/native/credentials', json=request, timeout=30)
    finally:
        if domain_host:
            client.close()
    response.raise_for_status()
    h.require(response.headers.get('Cache-Control') == 'no-store', 'generated credentials must not be cached')
    value = response.json()
    h.require(value.get('success'), value.get('msg', 'profile generation rejected'))
    profile = value.get('obj')
    h.require(isinstance(profile, dict) and profile.get('protocol') == protocol, 'unexpected profile response')
    if explicit:
        h.require(not profile.get('requirements'), 'explicit deployment inputs left unmet prerequisites')
        if protocol == 'dnstt':
            h.require(profile['settings'].get('domain') == DEPLOYMENT_INPUTS['dnstt']['domain'], 'explicit tunnel domain was changed')
        if protocol == 'openvpn':
            h.require(profile['settings']['tunnel'].get('dns') == [], 'OpenVPN invented external DNS values')
    h.require(len(profile['settings']['clients']) == 1, 'profile must generate exactly one account')
    return profile



def check_missing_deployment_inputs(panel):
    expected = {'orbit': 'serverAddress', 'anytls': 'serverName', 'dnstt': 'domain', 'shadowtls': 'handshake.address'}
    for protocol in PROTOCOLS:
        partial = request_profile(panel, protocol, explicit=False)
        fields = {item['field'] for item in partial.get('requirements', [])}
        h.require(fields == ({expected[protocol]} if protocol in expected else set()), 'wrong missing deployment requirements: ' + protocol)
        settings = partial['settings']
        if protocol == 'orbit':
            h.require('tls' not in settings and 'clientExport' not in settings and not settings['clients'][0].get('key'),
                      'Orbit inferred an endpoint/certificate/key without explicit input')
        elif protocol == 'anytls':
            h.require('clientExport' not in settings and not partial['streamSettings']['tlsSettings'].get('certificates'),
                      'AnyTLS inferred a certificate identity without explicit input')
        elif protocol == 'dnstt':
            h.require(settings['domain'] == '' and not settings.get('clientExport', {}).get('resolvers'),
                      'DNSTT invented domain or resolver values')
        elif protocol == 'shadowtls':
            h.require(settings['handshake']['address'] == '', 'ShadowTLS invented a cover target')
        elif protocol == 'openvpn':
            h.require(settings['tunnel'].get('dns') == [], 'OpenVPN invented DNS servers')
        h.result('profile.missing-deployment-inputs.' + protocol, True)
    # A domain-hosted panel must not fill in protocol endpoint/TLS identity.
    for protocol in ('orbit', 'anytls'):
        partial = request_profile(panel, protocol, domain_host=True, explicit=False)
        h.require({item['field'] for item in partial.get('requirements', [])} == {expected[protocol]},
                  'HTTP hostname was silently used as deployment input')
        h.require('clientExport' not in partial['settings'], 'panel hostname leaked into generated endpoint metadata')
        h.result('profile.no-host-inference.' + protocol, True)


def generate_cases(panel, work):
    cases = []
    for index, protocol in enumerate(PROTOCOLS):
        profile = request_profile(panel, protocol, domain_host=(protocol == 'orbit'))
        h.write_json(work / (protocol + '-profile.json'), profile)
        other = request_profile(panel, protocol)
        if protocol == 'orbit':
            h.require(profile['settings']['clientExport']['address'] == '127.0.0.1', 'explicit numeric Orbit endpoint was changed by panel hostname')
            h.require(other['settings']['clientExport']['address'] == '127.0.0.1', 'explicit numeric Orbit endpoint was changed by numeric panel host')
            h.result('profile.orbit-explicit-endpoint-independent-of-panel-host', True)
        first_user, next_user = profile['settings']['clients'][0], other['settings']['clients'][0]
        h.require(first_user['subId'] != next_user['subId'], 'new profiles reused subscription identity')
        field = {'orbit': 'key', 'dnstt': 'id', 'openvpn': 'privateKey', 'anytls': 'password',
                 'shadowtls': 'password', 'mieru': 'password'}[protocol]
        h.require(first_user[field] != next_user[field], 'new profiles reused account secret')
        h.result('profile.fresh-material.' + protocol, True)
        settings = copy.deepcopy(profile['settings'])
        edits = []
        if protocol == 'shadowtls':
            h.require(settings['handshake']['address'] == '127.0.0.1', 'generator changed cover address')
            settings['handshake']['port'] = h.TLS_PORT
            edits.append('handshake.port: 443 -> local controlled TLS port')
        case = {'name': 'generated-' + protocol, 'protocol': protocol, 'port': 29200 + index,
                'settings': settings, 'stream': profile.get('streamSettings') or {},
                'subid': first_user['subId'], 'udp': True, 'large': True, 'fixture_edits': edits}
        if protocol == 'openvpn':
            case['negative_tlscryptv2'] = next_user['tlsCryptV2']
        cases.append(case)
    h.write_json(work / 'fixture-edits.json', {c['protocol']: c['fixture_edits'] for c in cases})
    h.write_json(work / 'explicit-deployment-inputs.json', DEPLOYMENT_INPUTS)
    return cases


def string_leaves(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_leaves(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_leaves(child)


def assert_export(case, exported):
    protocol = case['protocol']
    outbound = next(o for o in exported['outbounds'] if o['tag'] == 'proxy')
    expected = {'dnstt': 'dns', 'shadowtls': 'shadowsocks'}.get(protocol, protocol)
    h.require(outbound['protocol'] == expected, 'export selected wrong protocol or direct fallback')
    if protocol == 'shadowtls':
        carrier = next(o for o in exported['outbounds'] if o['protocol'] == 'shadowtls')
        h.require(outbound['proxySettings']['tag'] == carrier['tag'], 'inner outbound is not chained through carrier')
        h.require(carrier['settings']['port'] == case['port'], 'carrier port changed')
        server = outbound['settings']['servers'][0]
        h.require(server['method'] == '2022-blake3-aes-256-gcm' and server.get('uotVersion') == 2,
                  'generated encrypted inner cipher or UDP framing changed')
    elif protocol == 'dnstt':
        tunnel = outbound['settings']['tunnel']
        h.require(tunnel['domain'] == case['settings']['domain'], 'generated tunnel domain changed')
        resolver = tunnel['resolvers'][0]
        h.require(resolver == {'transport': 'udp', 'address': '127.0.0.1:' + str(case['port'])},
                  'default DNS export is not the direct UDP resolver')
    elif protocol == 'openvpn':
        h.require(outbound['settings']['server']['port'] == case['port'], 'OpenVPN endpoint changed')
    else:
        h.require(outbound['settings']['port'] == case['port'], 'native endpoint changed')
    secrets = []
    settings = case['settings']
    if protocol == 'dnstt':
        secrets.append(settings['privateKey'])
    if protocol == 'orbit':
        secrets.append(next(line for line in settings['tls']['key'] if not line.startswith('-----')))
    if protocol == 'anytls':
        secrets.append(next(line for line in case['stream']['tlsSettings']['certificates'][0]['key'] if not line.startswith('-----')))
    if protocol == 'openvpn':
        # PKCS8's final lines contain its PUBLIC point, which can legitimately
        # appear in the exported CA certificate. Check private-scalar prefix
        # material, not that public suffix. Wrapping keys are wholly secret.
        for key in (settings['certificates']['key'], settings.get('clientExport', {}).get('issuerPrivateKey', '')):
            if key:
                secrets.append(next(line for line in key.splitlines() if not line.startswith('-----')))
        secrets.extend(settings['certificates'].get('tlsCryptV2', '').splitlines())
    leaves = list(string_leaves(exported))
    for secret in secrets:
        if len(secret) >= 40 and not secret.startswith('-----'):
            h.require(not any(secret in text for text in leaves), 'server-only key material leaked in export')


def reject_wrong_credentials(client, case, exported, folder):
    bad = copy.deepcopy(exported)
    proxy = next(o for o in bad['outbounds'] if o['tag'] == 'proxy')
    cfg = proxy['settings']
    protocol = case['protocol']
    if protocol == 'orbit':
        key = cfg['key']
        cfg['key'] = key[:5] + ('A' if key[5] != 'A' else 'B') + key[6:]
    elif protocol == 'dnstt':
        cfg['tunnel']['inner']['uuid'] = str(uuid.uuid4())
    elif protocol == 'openvpn':
        cfg['certificates']['tlsCryptV2'] = case['negative_tlscryptv2']
    elif protocol == 'shadowtls':
        next(o for o in bad['outbounds'] if o['protocol'] == 'shadowtls')['settings']['password'] = str(uuid.uuid4())
    else:
        cfg['password'] = str(uuid.uuid4())
    h.expect_denied(client, bad, folder, 'profile.wrong-credential-denied.' + protocol)


def configure(panel, cases, work):
    exports = {}
    for case in cases:
        obj = panel.api('POST', '/panel/api/inbounds/add', json=h.payload(case))
        case['id'] = obj['id']
        stored = panel.api('GET', '/panel/api/inbounds/get/' + str(obj['id']))
        persisted = json.loads(stored['settings'])
        comparable = copy.deepcopy(persisted)
        for user in comparable.get('clients', []):
            user.pop('created_at', None)
            user.pop('updated_at', None)
        h.require(comparable == case['settings'], 'generated settings changed during persistence')
        case['settings'] = persisted
        h.require(json.loads(stored['streamSettings']) == case['stream'], 'generated TLS transport changed during persistence')
        exported = panel.export(case['subid'])
        assert_export(case, exported)
        h.write_json(work / (case['protocol'] + '-export.json'), exported)
        exports[case['name']] = exported
        h.result('profile.persist-export.' + case['protocol'], True)
    panel.restart()
    return exports


def add_generated_clients(panel, initial_cases, exports, work, ordinal='second'):
    all_cases = list(initial_cases)
    for first in initial_cases:
        protocol = first['protocol']
        email = 'generated-' + ordinal + '-' + protocol + '@example.test'
        metadata = h.panel_client(email, ordinal + uuid.uuid4().hex)
        settings = first['settings']
        if protocol == 'openvpn':
            generated = panel.api('POST', '/panel/api/server/native/credentials', json={
                'kind': 'openvpn-client', 'email': email,
                'caCertificate': settings['certificates']['ca'],
                'issuerPrivateKey': settings['clientExport']['issuerPrivateKey'],
                'serverKey': settings['certificates'].get('tlsCryptV2', ''),
                'clientProofRequired': settings.get('clientProof', {}).get('required', False)})
            user = dict(metadata, **generated['client'])
        elif protocol == 'orbit':
            material = settings['tls']['certificate']
            certificate = '\n'.join(material) if isinstance(material, list) else material
            generated = panel.api('POST', '/panel/api/server/native/credentials', json={
                'kind': 'orbit', 'certificate': certificate})
            user = dict(metadata, key=generated['key'])
        elif protocol == 'dnstt':
            user = dict(metadata, id=str(uuid.uuid4()))
        elif protocol == 'mieru':
            user = dict(metadata, username=str(uuid.uuid4()), password=str(uuid.uuid4()))
        else:
            user = dict(metadata, password=str(uuid.uuid4()))
        h.require(user.get('email') == email and user.get('subId'), 'generated second client lacks identity')
        client_update = {'clients': [user]}
        if protocol == 'shadowtls':
            inner_user = {'email': email, 'level': 0, 'password': base64.b64encode(os.urandom(32)).decode()}
            client_update['inner'] = {'protocol': 'shadowsocks', 'settings': {'clients': [inner_user]}}
        panel.api('POST', '/panel/api/inbounds/addClient', json={
            'id': first['id'], 'settings': json.dumps(client_update)})
        row = panel.api('GET', '/panel/api/inbounds/get/' + str(first['id']))
        stored = json.loads(row['settings'])
        h.require(len(stored['clients']) == len(settings['clients']) + 1, 'new account not persisted')
        h.require(stored['clients'][0]['subId'] == first['subid'], 'second client changed first subscription')
        original = panel.export(first['subid'])
        h.require(original['outbounds'] == exports[first['name']]['outbounds'], 'adding client changed first export')
        second = dict(first, name=first['name'] + '-' + ordinal, subid=user['subId'], settings=stored)
        exported = panel.export(second['subid'])
        h.require(exported['outbounds'] != original['outbounds'], 'second account exported first credentials')
        assert_export(second, exported)
        h.write_json(work / (protocol + '-' + ordinal + '-export.json'), exported)
        exports[second['name']] = exported
        all_cases.append(second)
        h.result('profile.' + ordinal + '-account-create-export.' + protocol, True)
    panel.restart()
    return all_cases


def main(args):
    h.require(os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net') != os.environ['D11_HOST_NETNS'],
              'must run in private network namespace')
    work = args.work.resolve()
    h.require(not work.exists(), 'work path must be new')
    work.mkdir(parents=True, mode=0o700)
    args.work = work
    h.WORK_CREATED = True
    h.certificates(work / 'fixtures')
    # Only the locally controlled ShadowTLS cover uses this private CA. No
    # allowInsecure/skipVerify option is added to generated/exported profiles.
    os.environ['SSL_CERT_FILE'] = str(work / 'fixtures' / 'ca.crt')
    targets, udp = h.start_targets(work / 'fixtures')
    panel = h.Panel(work / 'panel-original', args.panel.resolve(), args.core.resolve())
    panel.init()
    panel.start()
    h.result('profile.isolated-panel-login', True)
    check_missing_deployment_inputs(panel)
    initial_cases = generate_cases(panel, work)
    exports = configure(panel, initial_cases, work)
    cases = add_generated_clients(panel, initial_cases, exports, work)
    for case in initial_cases:
        reject_wrong_credentials(args.client_core.resolve(), case, exports[case['name']],
                                 work / 'wrong-credential' / case['protocol'])
    for case in cases:
        h.traffic_client(args.client_core.resolve(), exports[case['name']], case,
                         work / 'client-before' / case['name'], 'profile.before')
    h.apply_outbound_template(panel, cases, exports)
    h.result('profile.native-outbound-template-roundtrip', True)
    h.traffic_outbounds(cases, exports, 'profile.before')
    response = panel.http.get(panel.url + '/panel/api/server/getDb', timeout=45)
    response.raise_for_status()
    h.require(response.content[:2] == b'PK', 'backup is not a portable archive')
    (work / 'profiles-backup.zip').write_bytes(response.content)
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        h.require('database.db' in archive.namelist(), 'portable backup lacks database')
    h.result('profile.portable-backup', True)
    h.stop(panel.p)
    restored = h.Panel(work / 'panel-restored', args.panel.resolve(), args.core.resolve())
    restored.init()
    restored.start()
    reply = restored.api('POST', '/panel/api/server/importDB', files={
        'db': ('profiles-backup.zip', response.content, 'application/zip')})
    h.wait_restore_reload(restored, reply, 'profile.restore-reload')
    rows = restored.api('GET', '/panel/api/inbounds/list')
    h.require(len(rows) == len(initial_cases), 'restore lost generated inbounds')
    h.result('profile.restore-all-generated-inbounds', True)
    for case in cases:
        exported = restored.export(case['subid'])
        h.require(exported['outbounds'] == exports[case['name']]['outbounds'], 'restore changed client credentials')
        h.result('profile.restore-exact-export.' + case['name'], True)
        h.traffic_client(args.client_core.resolve(), exported, case,
                         work / 'client-restored' / case['name'], 'profile.restored')
    h.traffic_outbounds(cases, exports, 'profile.restored')
    openvpn = copy.deepcopy(next(c for c in initial_cases if c['protocol'] == 'openvpn'))
    persisted = restored.api('GET', '/panel/api/inbounds/get/' + str(openvpn['id']))
    openvpn['settings'] = json.loads(persisted['settings'])
    third = add_generated_clients(restored, [openvpn], exports, work, 'third')[-1]
    h.traffic_client(args.client_core.resolve(), exports[third['name']], third,
                     work / 'client-after-restore-issued', 'profile.issued-after-restore')
    h.stop(restored.p)
    for server in targets:
        server.shutdown()
    udp.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('panel', 'core', 'client-core', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    completed = False
    try:
        main(args)
        completed = True
    except Exception as exc:
        h.result('profile.harness-completion', False, exc)
        traceback.print_exc()
    finally:
        for proc in reversed(h.PROCESSES):
            h.stop(proc)
        if h.WORK_CREATED:
            binaries = {}
            for name in ('panel', 'core', 'client_core'):
                path = getattr(args, name).resolve()
                binaries[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            h.write_json(args.work / 'results.json', {'completed': completed, 'passed': sum(r['ok'] for r in h.RESULTS),
                'failed': sum(not r['ok'] for r in h.RESULTS), 'network': 'private namespace; controlled local targets only',
                'binaries': binaries, 'client_endpoint_mapping': 'off (existing client setting)',
                'shadowtls_cover_trust': 'test-local CA via SSL_CERT_FILE; verification remains enabled', 'results': h.RESULTS})
            print('RESULTS ' + str(args.work / 'results.json'), flush=True)
    sys.exit(1 if not completed or any(not r['ok'] for r in h.RESULTS) else 0)
