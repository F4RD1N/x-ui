'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const plain = value => JSON.parse(JSON.stringify(value));
const UUID = '11111111-2222-4333-8444-555555555555';
const CERT = '-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----';
const KEY = '-----BEGIN PRIVATE KEY-----\nFIXTURE\n-----END PRIVATE KEY-----';

function fixture() {
    let n = 0;
    const location = {};
    Object.defineProperty(location, 'hostname', {get() {throw new Error('Deployment identity must not read the page hostname');}});
    const ctx = vm.createContext({console, TextEncoder, URL, location,
        btoa: value => Buffer.from(value, 'binary').toString('base64'),
        ObjectUtil: {isEmpty: value => value === null || value === undefined || value === '', isArrEmpty: value => !value || !value.length, clone: value => value === undefined ? undefined : plain(value), cloneProps: (to, from) => Object.assign(to, from)},
        RandomUtil: {randomUUID: () => UUID, randomLowerAndNum: () => `fixture${++n}`, randomSeq: () => `fixture${++n}`, randomInteger: () => 18080, randomShortIds: () => ['1234567890abcdef'], randomShadowsocksPassword: () => 'fixture-password'},
        Wireguard: {generateKeypair: () => ({publicKey: 'fixture-public', privateKey: 'fixture-private'})},
        NumberFormatter: {toFixed: (number, precision) => Number(number.toFixed(precision))}, SizeFormatter: {ONE_GB: 1073741824},
    });
    for (const file of ['inbound.js', 'native-inbound.js']) vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model', file), 'utf8'), ctx);
    vm.runInContext('globalThis.NativeSettings = Inbound.NativeSettings;', ctx);
    return ctx;
}

function generated(protocol) {
    const client = {email: 'generated-client', subId: 'generated-sub', enable: true, level: 0};
    const base = {clients: [client]};
    if (protocol === 'anytls') return {...base, clients: [{...client, password: UUID}], handshakeTimeout: 10};
    if (protocol === 'mieru') return {...base, transport: 'tcp', clients: [{...client, username: UUID, password: UUID}]};
    if (protocol === 'dnstt') return {...base, privateKey: 'ab'.repeat(32), inner: {protocol: 'vless'}, clients: [{...client, id: UUID}]};
    if (protocol === 'openvpn') return {...base, network: 'udp', certificates: {ca: CERT, cert: CERT, key: KEY}, crypto: {dataCiphers: ['AES-256-GCM'], authHash: 'SHA256'}, tunnel: {ipv4: '10.88.0.0/24', dns: [], mtu: 1400}, clients: [{...client, commonName: 'generated-cn', certificate: CERT, privateKey: KEY}]};
    if (protocol === 'shadowtls') return {...base, version: 3, handshake: {port: 443}, clients: [{...client, password: UUID}], inner: {protocol: 'shadowsocks', settings: {network: 'tcp', method: '2022-blake3-aes-256-gcm', password: Buffer.alloc(32, 1).toString('base64'), clients: [{email: client.email, password: Buffer.alloc(32, 2).toString('base64')}]}}};
    return {...base, transport: 'tcp', tls: {certificate: CERT.split('\n'), key: KEY.split('\n')}, clients: [{...client, key: 'vck1_' + 'A'.repeat(86)}]};
}

const get = (object, key) => key.split('.').reduce((value, part) => value?.[part], object);
const blank = value => value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
for (const protocol of ['anytls', 'orbit', 'dnstt', 'openvpn', 'shadowtls', 'mieru']) test(`new ${protocol} defaults contain no external deployment choices`, () => {
    const {NativeSettings} = fixture();
    const settings = new NativeSettings(protocol);
    for (const field of ['domain', 'handshake.address', 'host', 'peer', 'reality.dest', 'reality.serverNames', 'clientExport.serverName', 'clientExport.address', 'clientExport.resolvers', 'clientExport.resolver', 'server.address']) {
        assert.ok(blank(get(settings.data, field)), `${protocol}.${field} must be blank`);
    }
    if (protocol === 'openvpn') {
        assert.deepEqual(plain(settings.data.tunnel.dns), []);
        assert.equal(settings.data.tunnel.ipv4, '10.88.0.0/24');
        assert.equal(settings.data.tunnel.mtu, 1400);
    }
    if (protocol === 'orbit') assert.equal(settings.data.path, '/core', 'approved local protocol path is retained');
});

test('AnyTLS identity requires explicit valid input and never the page hostname', () => {
    const {NativeSettings} = fixture();
    const settings = new NativeSettings('anytls');
    assert.ok(settings.profileRequiresIdentity);
    for (const value of [undefined, '', ' ', 'https://vpn.example', '*.example', 'name:443', 'bad name', 'éxample.test']) {
        settings.data.clientExport = value === undefined ? {} : {serverName: value};
        assert.ok(settings.profileIdentityError, String(value));
    }
    for (const value of ['vpn.example', '127.0.0.1', '2001:db8::1', '[2001:db8::1]']) {
        settings.data.clientExport = {serverName: value};
        assert.equal(settings.profileIdentityError, '', value);
        assert.equal(settings.data.clientExport.serverName, value, 'identity checks must not rewrite input');
    }
});

test('Orbit identity requires explicit numeric address and does not use DNS/page host', () => {
    const {NativeSettings} = fixture();
    const settings = new NativeSettings('orbit');
    for (const value of [undefined, '', 'vpn.example', '127.0.0.1:443', 'https://127.0.0.1', '999.1.1.1', '0.0.0.0', '::']) {
        settings.data.clientExport = value === undefined ? {} : {address: value};
        assert.ok(settings.profileIdentityError, String(value));
    }
    for (const value of ['192.0.2.9', '127.0.0.1', '2001:db8::1', '[2001:db8::1]']) {
        settings.data.clientExport = {address: value};
        assert.equal(settings.profileIdentityError, '', value);
        assert.equal(settings.data.clientExport.address, value);
    }
    const imported = new NativeSettings('orbit', generated('orbit'));
    assert.equal(imported.profileIdentityError, '', 'imported profiles must not trigger new issuance prerequisites');
});

for (const protocol of ['dnstt', 'shadowtls']) for (const missing of [undefined, '']) test(`${protocol} generated credentials may omit only its external prerequisite (${String(missing)})`, () => {
    const {NativeSettings} = fixture();
    const data = generated(protocol);
    if (protocol === 'dnstt') { if (missing !== undefined) data.domain = missing; }
    else if (missing !== undefined) data.handshake.address = missing;
    const settings = new NativeSettings(protocol, data);
    assert.deepEqual(plain(settings.generatedProfileErrors), []);
    assert.ok(settings.validationErrors.length, 'normal Save validation must still reject the missing deployment field');
});

test('generated validation does not relax missing deployment fields for Orbit WS/Reality', () => {
    const {NativeSettings} = fixture();
    const ws = generated('orbit'); ws.transport = 'ws';
    assert.ok(new NativeSettings('orbit', ws).generatedProfileErrors.some(error => /host/i.test(error)));
    const reality = generated('orbit'); reality.security = 'reality'; reality.reality = {privateKey: 'A'.repeat(43), shortIds: ['0123456789abcdef']};
    assert.ok(new NativeSettings('orbit', reality).generatedProfileErrors.some(error => /server names|destination/i.test(error)));
});

for (const protocol of ['dnstt', 'shadowtls']) test(`${protocol} malformed nonblank deployment input is never treated as absent`, () => {
    const {NativeSettings} = fixture();
    const invalid = protocol === 'dnstt' ? [' ', null, 123, 'single-label', 'bad..name', '.bad.example', 'https://bad.example', 'bad name.example'] : [' ', null, 123, 'https://cover.example', 'cover.example:443', 'bad name', '*.example'];
    for (const value of invalid) {
        const data = generated(protocol);
        if (protocol === 'dnstt') data.domain = value;
        else data.handshake.address = value;
        assert.ok(new NativeSettings(protocol, data).generatedProfileErrors.length, JSON.stringify(value));
    }
});

test('relaxed generated validation still rejects malformed keys and users', () => {
    const {NativeSettings} = fixture();
    const cases = [
        ['dnstt', data => {data.privateKey = 'not-hex';}],
        ['dnstt', data => {data.clients[0].id = 'not-a-uuid';}],
        ['anytls', data => {data.clients[0].password = '';}],
        ['mieru', data => {data.clients[0].username = '';}],
        ['orbit', data => {data.clients[0].key = 'bad';}],
        ['openvpn', data => {data.certificates.key = 'not-pem';}],
        ['openvpn', data => {data.clients[0].commonName = '';}],
        ['shadowtls', data => {data.clients[0].password = '';}],
        ['shadowtls', data => {data.inner.settings.clients[0].password = '';}],
    ];
    for (const [protocol, mutate] of cases) {
        const data = generated(protocol); mutate(data);
        assert.ok(new NativeSettings(protocol, data).generatedProfileErrors.length, protocol);
    }
});

test('generated validation never accepts plaintext ShadowTLS inner settings', () => {
    const {NativeSettings} = fixture();
    const shadow = generated('shadowtls'); shadow.inner.settings.method = 'none';
    assert.ok(new NativeSettings('shadowtls', shadow).generatedProfileErrors.length);
});

for (const protocol of ['anytls', 'orbit']) test(`${protocol} profile retries may use a changed explicit deployment identity`, () => {
    const {NativeSettings} = fixture();
    const settings = new NativeSettings(protocol);
    const before = {settings: settings.toJson(), streamSettings: {network: 'tcp'}};
    before.settings.clientExport = protocol === 'anytls' ? {serverName: 'first.example'} : {address: '192.0.2.1'};
    const current = plain(before);
    current.settings.clientExport = protocol === 'anytls' ? {serverName: 'second.example'} : {address: '192.0.2.2'};
    const issued = {protocol, settings: generated(protocol)};
    issued.settings.clientExport = plain(current.settings.clientExport);
    const result = NativeSettings.mergeGeneratedProfile(protocol, issued, before, current);
    assert.deepEqual(plain(result.settings.clientExport), current.settings.clientExport);
    assert.equal(result.settings.clients[0].email, current.settings.clients[0].email);
    assert.equal(result.settings.clients[0].subId, current.settings.clients[0].subId);
});

test('profile merge never overwrites manual secret edits made during issuance', () => {
    const {NativeSettings} = fixture();
    const cases = [
        ['dnstt', value => {value.settings.privateKey = 'manual-private';}],
        ['orbit', value => {value.settings.tls.key = ['manual-private'];}],
        ['openvpn', value => {value.settings.certificates.key = 'manual-private';}],
        ['openvpn', value => {value.settings.clientExport = {issuerPrivateKey: 'manual-issuer'};}],
        ['shadowtls', value => {value.settings.inner.settings.accounts = [{user: 'manual', pass: 'manual'}];}],
        ['mieru', value => {value.settings.clients[0].password = 'manual-password';}],
        ['anytls', value => {value.streamSettings.tlsSettings = {certificates: [{certificate: CERT.split('\n'), key: ['manual']}]} ;}],
    ];
    for (const [protocol, mutate] of cases) {
        const settings = new NativeSettings(protocol);
        const before = {settings: settings.toJson(), streamSettings: {network: 'tcp'}};
        const current = plain(before); mutate(current);
        const unchanged = plain(current);
        assert.throws(() => NativeSettings.mergeGeneratedProfile(protocol, {protocol, settings: generated(protocol)}, before, current), /changed/i, protocol);
        assert.deepEqual(current, unchanged);
    }
});

test('safe explicit deployment values present in the initial snapshot survive generated responses', () => {
    const {NativeSettings} = fixture();
    const cases = [
        ['dnstt', {domain: 'owned.example', clientExport: {resolvers: [{transport: 'udp', address: '192.0.2.53:53'}]}}],
        ['shadowtls', {handshake: {address: 'cover.example', port: 8443}}],
        ['anytls', {clientExport: {serverName: 'tls.example'}}],
        ['orbit', {clientExport: {address: '192.0.2.9'}}],
        ['openvpn', {tunnel: {ipv4: '10.88.0.0/24', dns: ['192.0.2.53'], mtu: 1400}}],
    ];
    for (const [protocol, explicit] of cases) {
        const base = new NativeSettings(protocol).toJson();
        const before = {settings: {...base, ...plain(explicit)}, streamSettings: {network: 'tcp'}};
        const issued = {protocol, settings: generated(protocol)};
        const merged = NativeSettings.mergeGeneratedProfile(protocol, issued, before, plain(before));
        for (const [field, value] of Object.entries(explicit)) assert.deepEqual(plain(merged.settings[field]), value, `${protocol}.${field}`);
    }
});

test('generated trust material survives an explicitly entered identity with no prior export container', () => {
    const {NativeSettings} = fixture();
    for (const protocol of ['anytls', 'openvpn']) {
        const before = {settings: new NativeSettings(protocol).toJson(), streamSettings: {network: 'tcp'}};
        const current = plain(before); current.settings.clientExport = {serverName: 'chosen.example'};
        const issued = {protocol, settings: generated(protocol)};
        issued.settings.clientExport = {serverName: 'chosen.example', ...(protocol === 'anytls' ? {ca: CERT} : {issuerPrivateKey: KEY})};
        const merged = NativeSettings.mergeGeneratedProfile(protocol, issued, before, current);
        assert.equal(merged.settings.clientExport.serverName, 'chosen.example');
        assert.equal(merged.settings.clientExport[protocol === 'anytls' ? 'ca' : 'issuerPrivateKey'], protocol === 'anytls' ? CERT : KEY);
    }
});

test('profile merge discards unsolicited external defaults while retaining generated keys', () => {
    const {NativeSettings} = fixture();
    const before = {settings: new NativeSettings('dnstt').toJson(), streamSettings: {network: 'tcp'}};
    const issued = {protocol: 'dnstt', settings: {...generated('dnstt'), domain: 'invented.example', host: 'invented.example', clientExport: {serverName: 'invented.example', address: '192.0.2.1', resolvers: [{transport: 'udp', address: '192.0.2.53:53'}]}}};
    const merged = NativeSettings.mergeGeneratedProfile('dnstt', issued, before, plain(before));
    for (const field of ['domain', 'host', 'clientExport.serverName', 'clientExport.address', 'clientExport.resolvers']) assert.ok(blank(get(merged.settings, field)), field);
    assert.equal(merged.settings.privateKey, issued.settings.privateKey);
    assert.equal(merged.settings.clients[0].id, UUID);
});

test('explicit certificate identities canonicalize equivalent notation without inferring another identity', () => {
    const {NativeSettings} = fixture();
    for (const [input, expected] of [[' 127.0.0.1 ', '127.0.0.1'], [' [2001:0db8::1] ', '2001:db8::1'], [' VPN.Example. ', 'vpn.example'], ['', ''], [undefined, '']]) {
        assert.equal(NativeSettings.canonicalServerIdentity(input), expected);
        assert.equal(NativeSettings.canonicalServerIdentity(expected), expected);
    }
    assert.notEqual(NativeSettings.canonicalServerIdentity('first.example'), NativeSettings.canonicalServerIdentity('second.example'));
});

test('generated identity merge keeps CA and entered endpoint semantics while normalizing export notation', () => {
    const {NativeSettings} = fixture();
    for (const [protocol, field, input, expected] of [['anytls', 'serverName', ' [::1] ', '::1'], ['anytls', 'serverName', ' TLS.Example. ', 'tls.example'], ['orbit', 'address', ' [2001:0db8::9] ', '2001:db8::9']]) {
        const before = {settings: new NativeSettings(protocol).toJson(), streamSettings: {network: 'tcp'}};
        const current = plain(before); current.settings.clientExport = {[field]: input};
        const issued = {protocol, settings: generated(protocol)};
        issued.settings.clientExport = {[field]: expected, ca: CERT};
        const merged = NativeSettings.mergeGeneratedProfile(protocol, issued, before, current);
        assert.equal(merged.settings.clientExport[field], expected);
        assert.equal(merged.settings.clientExport.ca, CERT);
        assert.equal(current.settings.clientExport[field], input, 'snapshot remains untouched');
    }
});
