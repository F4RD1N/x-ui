'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const plain = value => JSON.parse(JSON.stringify(value));
const cert = '-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----';
const key = '-----BEGIN PRIVATE KEY-----\nFIXTURE\n-----END PRIVATE KEY-----';
const wrapped = '-----BEGIN OpenVPN tls-crypt-v2 client key-----\nFIXTURE\n-----END OpenVPN tls-crypt-v2 client key-----';

function fixture(protocol, data) {
    let n = 0;
    const ctx = vm.createContext({console, TextEncoder, URL, Uint8Array, crypto: webcrypto, AbortController, setTimeout, clearTimeout,
        btoa: value => Buffer.from(value, 'binary').toString('base64'), location: {hostname: 'panel.example'},
        ObjectUtil: {isEmpty: value => value === null || value === undefined || value === '', isArrEmpty: value => !value || !value.length, clone: value => value === undefined ? undefined : plain(value), cloneProps: (to, from) => Object.assign(to, from)},
        RandomUtil: {randomUUID: () => '11111111-2222-4333-8444-' + String(++n).padStart(12, '0'), randomLowerAndNum: () => `fixture${++n}`, randomSeq: () => `fixture${++n}`, randomInteger: () => 18080, randomShortIds: () => ['1234567890abcdef'], randomShadowsocksPassword: () => 'fixture-password'},
        Wireguard: {generateKeypair: () => ({publicKey: 'fixture-public', privateKey: 'fixture-private'})},
        NumberFormatter: {toFixed: (number, precision) => Number(number.toFixed(precision))}, SizeFormatter: {ONE_GB: 1073741824},
    });
    for (const file of ['inbound.js', 'native-inbound.js', 'native-creation.js']) vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model', file), 'utf8'), ctx);
    ctx.protocol = protocol; ctx.input = data;
    vm.runInContext('globalThis.settings = new Inbound.NativeSettings(protocol,input); globalThis.NativeSettings = Inbound.NativeSettings;', ctx);
    return ctx;
}

function base(protocol) {
    const clients = [{email: 'existing', subId: 'existing-sub', enable: true, level: 0, futureClient: {keep: true}}];
    const shared = {clients, futureServer: {keep: true}};
    if (protocol === 'anytls') return {...shared, clients: [{...clients[0], password: 'existing-password'}]};
    if (protocol === 'mieru') return {...shared, transport: 'tcp', clients: [{...clients[0], username: 'existing-user', password: 'existing-password'}]};
    if (protocol === 'dnstt') return {...shared, domain: 't.example', privateKey: '11'.repeat(32), inner: {protocol: 'vless'}, clients: [{...clients[0], id: '11111111-2222-4333-8444-555555555555'}]};
    if (protocol === 'orbit') return {...shared, tls: {certificate: cert.split('\n'), key: key.split('\n')}, clients: [{...clients[0], key: 'vck1_' + 'A'.repeat(86)}]};
    if (protocol === 'openvpn') return {...shared, certificates: {ca: cert, cert, key, tlsCryptV2: 'server-wrapping-key'}, clientExport: {issuerPrivateKey: 'issuer-private'}, clientProof: {required: true}, clients: [{...clients[0], commonName: 'existing-cn'}]};
    return {...shared, version: 3, strict: true, handshake: {address: 'tls.example', port: 443}, clients: [{...clients[0], password: 'existing-outer', innerUsername: 'existing'}], inner: {protocol: 'socks', settings: {auth: 'password', udp: false, accounts: [{user: 'existing', pass: 'existing-inner'}]}}};
}

for (const protocol of ['anytls', 'mieru', 'dnstt']) test(`${protocol}: adds unique secure credentials and preserves existing data`, async () => {
    const ctx = fixture(protocol, base(protocol));
    const before = plain(ctx.settings.toJson());
    const added = await ctx.settings.addGeneratedClient();
    assert.ok(added);
    assert.deepEqual(plain(added.validationErrors), []);
    assert.ok(added.email && added.subId);
    assert.deepEqual(plain(ctx.settings.toJson().clients[0]), before.clients[0]);
    const after = plain(ctx.settings.toJson()); delete after.clients; delete before.clients;
    assert.deepEqual(after, before);
    const secret = added.data.password || added.data.id;
    assert.match(secret, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(secret.slice(0, 8), '11111111', 'uses Web Crypto instead of metadata RNG');
    const second = await ctx.settings.addGeneratedClient();
    assert.ok(second);
    assert.notEqual(second.data.password || second.data.id, secret);
});

test('DNSTT SOCKS binds accounting username to new email', async () => {
    const data = base('dnstt'); data.inner.protocol = 'socks';
    const ctx = fixture('dnstt', data);
    const client = await ctx.settings.addGeneratedClient();
    assert.equal(client.data.username, client.email);
    assert.ok(client.data.password);
});

for (const reality of [false, true]) test(`Orbit issues a new key bound to current ${reality ? 'Reality' : 'certificate'}`, async () => {
    const data = base('orbit');
    if (reality) { data.security = 'reality'; data.reality = {privateKey: 'reality-private'}; }
    const ctx = fixture('orbit', data);
    let request;
    ctx.NativeSettings.requestCredentials = async value => {request = plain(value); return {key: 'vck1_' + 'B'.repeat(86)};};
    const before = plain(ctx.settings.toJson());
    const client = await ctx.settings.addGeneratedClient();
    assert.ok(client);
    assert.deepEqual(request, reality ? {kind: 'orbit', realityPrivateKey: 'reality-private'} : {kind: 'orbit', certificate: cert});
    assert.deepEqual(plain(ctx.settings.toJson().clients[0]), before.clients[0]);
    assert.equal(client.data.key, 'vck1_' + 'B'.repeat(86));
});

test('OpenVPN issues a client with exact CA/proof/wrapping request and keeps local metadata', async () => {
    const ctx = fixture('openvpn', base('openvpn'));
    let request;
    ctx.NativeSettings.requestCredentials = async value => {
        request = plain(value);
        return {client: {commonName: 'issued-client', certificate: cert, privateKey: key, tlsCryptV2: wrapped, clientProof: {keyId: 'proof-id', key: 'ab'.repeat(32)}, email: 'wrong-remote-email', subId: 'wrong-remote-sub', enable: false, totalGB: 999}};
    };
    const before = plain(ctx.settings.toJson());
    const client = await ctx.settings.addGeneratedClient();
    assert.ok(client);
    assert.deepEqual(request, {kind: 'openvpn-client', email: client.email, caCertificate: cert, issuerPrivateKey: 'issuer-private', serverKey: 'server-wrapping-key', clientProofRequired: true});
    assert.equal(client.data.commonName, 'issued-client');
    assert.equal(client.data.clientProof.keyId, 'proof-id');
    assert.notEqual(client.email, 'wrong-remote-email');
    assert.notEqual(client.subId, 'wrong-remote-sub');
    assert.equal(client.enable, true);
    assert.deepEqual(plain(ctx.settings.toJson().clients[0]), before.clients[0]);
    delete before.clients;
    assert.deepEqual(plain(ctx.settings.data), before);
});

for (const variant of ['socks', 'vless', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'chacha20-ietf-poly1305']) test(`ShadowTLS adds matching ${variant} account without changing server or existing credentials`, async () => {
    const data = base('shadowtls');
    if (variant === 'vless') data.inner = {protocol: 'vless', settings: {decryption: 'none', clients: [{email: 'existing', id: '11111111-2222-4333-8444-555555555555'}]}};
    else if (variant !== 'socks') data.inner = {protocol: 'shadowsocks', settings: {network: 'tcp', method: variant, password: 'existing-server-key', clients: [{email: 'existing', password: 'existing-inner', method: variant}]}};
    const ctx = fixture('shadowtls', data);
    const before = plain(ctx.settings.toJson());
    const client = await ctx.settings.addGeneratedClient();
    assert.ok(client, ctx.settings.generationError);
    assert.deepEqual(plain(ctx.settings.toJson().clients[0]), before.clients[0]);
    const listName = variant === 'socks' ? 'accounts' : 'clients';
    const inner = plain(ctx.settings.data.inner);
    assert.deepEqual(inner.settings[listName][0], before.inner.settings[listName][0]);
    assert.equal(inner.settings[listName].length, 2);
    const subset = plain(ctx.settings.generatedClientInner(client));
    assert.deepEqual(Object.keys(subset.settings), [listName]);
    assert.equal(subset.settings[listName].length, 1);
    const account = subset.settings[listName][0];
    if (variant === 'socks') assert.equal(account.user, client.data.innerUsername);
    else assert.equal(account.email, client.email);
    if (variant.startsWith('2022-')) assert.equal(Buffer.from(account.password, 'base64').length, variant.includes('128') ? 16 : 32);
    assert.equal(ctx.settings.data.inner.settings.password, data.inner.settings.password);
    assert.equal(ctx.settings.generatedClientInner(ctx.settings.clients[0]), null);
    if (variant !== 'socks') { client.email = 'renamed'; assert.equal(ctx.settings.generatedClientInner(client).settings.clients[0].email, 'renamed'); }
});

for (const version of [1, 2]) test(`ShadowTLS v${version} preserves shared outer material`, async () => {
    const data = base('shadowtls'); data.version = version; data.password = 'shared-outer';
    const ctx = fixture('shadowtls', data);
    const client = await ctx.settings.addGeneratedClient();
    assert.ok(client); assert.equal(ctx.settings.data.password, 'shared-outer'); assert.equal(client.data.password, undefined);
});

test('failed server response and missing issuer do not append or mutate', async () => {
    for (const mode of ['http', 'bad-key', 'issuer', 'missing-wrap', 'missing-proof']) {
        const protocol = mode === 'http' || mode === 'bad-key' ? 'orbit' : 'openvpn';
        const ctx = fixture(protocol, base(protocol));
        if (mode === 'issuer') delete ctx.settings.data.clientExport.issuerPrivateKey;
        ctx.NativeSettings.requestCredentials = async () => {
            if (mode === 'http') throw new Error('request failed');
            if (mode === 'bad-key') return {key: 'bad'};
            return {client: {commonName: 'issued', certificate: cert, privateKey: key, ...(mode === 'missing-proof' ? {tlsCryptV2: wrapped} : {})}};
        };
        const before = plain(ctx.settings.toJson());
        assert.equal(await ctx.settings.addGeneratedClient(), null, mode);
        assert.deepEqual(plain(ctx.settings.toJson()), before, mode);
        assert.ok(ctx.settings.generationError);
        assert.equal(ctx.settings.generating, false);
    }
});

test('pending duplicate click is coalesced and stale form edits are preserved', async () => {
    const ctx = fixture('orbit', base('orbit'));
    let resolve, calls = 0;
    ctx.NativeSettings.requestCredentials = () => {calls++; return new Promise(done => {resolve = done;});};
    const pending = ctx.settings.addGeneratedClient();
    assert.equal(await ctx.settings.addGeneratedClient(), null);
    assert.equal(calls, 1);
    ctx.settings.data.futureServer.edited = true;
    resolve({key: 'vck1_' + 'B'.repeat(86)});
    assert.equal(await pending, null);
    assert.equal(ctx.settings.clients.length, 1);
    assert.equal(ctx.settings.data.futureServer.edited, true);
    assert.match(ctx.settings.generationError, /changed/);
});

test('duplicate credential and metadata identities fail without appending', async () => {
    const ctx = fixture('orbit', base('orbit'));
    ctx.NativeSettings.requestCredentials = async () => ({key: 'vck1_' + 'A'.repeat(86)});
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.addGeneratedClient(), null);
    assert.match(ctx.settings.generationError, /already exist/);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
    ctx.RandomUtil.randomLowerAndNum = () => 'existing';
    assert.equal(await ctx.settings.addGeneratedClient(), null);
    assert.match(ctx.settings.generationError, /unique client/);
});

test('secure entropy missing and unsupported inner cipher fail closed', async () => {
    const ctx = fixture('anytls', base('anytls')); ctx.crypto = undefined;
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.addGeneratedClient(), null);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
    const data = base('shadowtls'); data.inner = {protocol: 'shadowsocks', settings: {method: 'none', clients: [{email: 'existing', password: 'existing'}]}};
    const shadow = fixture('shadowtls', data);
    const old = plain(shadow.settings.toJson());
    assert.equal(await shadow.settings.addGeneratedClient(), null);
    assert.deepEqual(plain(shadow.settings.toJson()), old);
});

test('full-form email edits synchronize only generated inner account without key rotation', async () => {
    const data = base('shadowtls');
    data.inner = {protocol: 'shadowsocks', settings: {method: '2022-blake3-aes-256-gcm', password: 'server-key', clients: [{email: 'existing', password: 'existing-key'}]}};
    const ctx = fixture('shadowtls', data);
    const client = await ctx.settings.addGeneratedClient();
    const secret = ctx.settings.data.inner.settings.clients[1].password;
    client.email = 'renamed-generated';
    assert.equal(ctx.settings.syncGeneratedClientBindings(), true);
    const accounts = plain(ctx.settings.data.inner.settings.clients);
    assert.deepEqual(accounts[0], data.inner.settings.clients[0]);
    assert.equal(accounts[1].email, client.email);
    assert.equal(accounts[1].password, secret);
    assert.equal(ctx.settings.generatedClientInner(client).settings.clients[0].email, client.email);
});

test('remembered initial-profile binding follows edited email but is never a new-account subset', () => {
    const data = base('shadowtls');
    data.inner = {protocol: 'vless', settings: {decryption: 'none', clients: [{email: 'existing', id: '11111111-2222-4333-8444-555555555555'}]}};
    const ctx = fixture('shadowtls', data);
    ctx.settings.rememberClientBindings();
    ctx.settings.clients[0].email = 'renamed-initial';
    assert.equal(ctx.settings.syncGeneratedClientBindings(), true);
    assert.equal(ctx.settings.data.inner.settings.clients[0].email, 'renamed-initial');
    assert.equal(ctx.settings.data.inner.settings.clients[0].id, data.inner.settings.clients[0].id);
    assert.equal(ctx.settings.generatedClientInner(ctx.settings.clients[0]), null);
});

test('changed credential or duplicate identity rejects binding synchronization atomically', async () => {
    const data = base('shadowtls');
    data.inner = {protocol: 'vless', settings: {decryption: 'none', clients: [{email: 'existing', id: '11111111-2222-4333-8444-555555555555'}]}};
    const ctx = fixture('shadowtls', data);
    ctx.settings.rememberClientBindings();
    const added = await ctx.settings.addGeneratedClient();
    added.email = 'existing';
    let before = plain(ctx.settings.toJson());
    assert.throws(() => ctx.settings.syncGeneratedClientBindings(), /unique/);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
    added.email = 'new-name';
    ctx.settings.data.inner.settings.clients[1].id = 'changed';
    before = plain(ctx.settings.toJson());
    assert.throws(() => ctx.settings.syncGeneratedClientBindings(), /binding changed/);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});
