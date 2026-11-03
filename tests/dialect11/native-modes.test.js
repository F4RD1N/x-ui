'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const plain = value => JSON.parse(JSON.stringify(value));
const uuid = '11111111-2222-4333-8444-555555555555';
const cert = ['-----BEGIN CERTIFICATE-----', 'FIXTURE', '-----END CERTIFICATE-----'];
const key = ['-----BEGIN PRIVATE KEY-----', 'FIXTURE', '-----END PRIVATE KEY-----'];
function fixture(protocol, input) {
    let count = 0;
    const ctx = vm.createContext({console, TextEncoder, URL, Uint8Array, crypto: webcrypto, AbortController, setTimeout, clearTimeout,
        btoa: value => Buffer.from(value, 'binary').toString('base64'), location: {hostname: 'panel.example'},
        ObjectUtil: {isEmpty: value => value === null || value === undefined || value === '', isArrEmpty: value => !value || !value.length, clone: value => value === undefined ? undefined : plain(value), cloneProps: (to, from) => Object.assign(to, from)},
        RandomUtil: {randomUUID: () => uuid, randomLowerAndNum: () => `fixture${++count}`, randomSeq: () => `fixture${++count}`, randomInteger: () => 18080, randomShortIds: () => ['1234567890abcdef'], randomShadowsocksPassword: () => 'fixture-password'},
        Wireguard: {generateKeypair: () => ({publicKey: 'fixture-public', privateKey: 'fixture-private'})},
        NumberFormatter: {toFixed: (number, precision) => Number(number.toFixed(precision))}, SizeFormatter: {ONE_GB: 1073741824},
    });
    for (const file of ['inbound.js', 'native-inbound.js', 'native-modes.js']) vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model', file), 'utf8'), ctx);
    ctx.protocol = protocol; ctx.input = input;
    vm.runInContext('globalThis.settings = new Inbound.NativeSettings(protocol,input); globalThis.NativeSettings = Inbound.NativeSettings;', ctx);
    return ctx;
}
const orbit = () => ({transport: 'tcp', tls: {certificate: cert, key}, clients: [{email: 'existing', key: 'vck1_' + 'A'.repeat(86)}], future: {keep: true}});
const dnstt = () => ({domain: 't.example', privateKey: '11'.repeat(32), inner: {protocol: 'vless'}, clients: [{email: 'existing', id: uuid, level: 2, custom: 'keep'}]});
const openvpn = clients => ({network: 'udp', certificates: {ca: cert.join('\n'), cert: cert.join('\n'), key: key.join('\n')}, clientProof: {required: true}, clients});

test('WSS fills its local path only, leaves external fields blank and never fabricates an outer certificate', async () => {
    const data = orbit(); data.transport = 'wss';
    const ctx = fixture('orbit', data);
    ctx.NativeSettings.requestCredentials = async () => {throw new Error('must not generate TLS material');};
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.data.host, undefined);
    assert.equal(ctx.settings.data.path, '/core');
    assert.equal(ctx.settings.data.outerTls, undefined);
    assert.deepEqual(plain(ctx.settings.data.tls), before.tls);
    assert.deepEqual(plain(ctx.settings.toJson().clients), before.clients);
    assert.ok(ctx.settings.validationErrors.some(error => error.includes('WSS outer certificate')));
});

test('WSS preserves supplied certificate pair, host/path, and all client keys', async () => {
    const data = orbit(); Object.assign(data, {transport: 'wss', host: 'custom.example', path: '/custom', outerTls: {certificate: cert, key, future: 42}});
    const ctx = fixture('orbit', data);
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('IP-address panels never invent WebSocket Host or peer from their address', async () => {
    for (const transport of ['ws', 'wss']) for (const address of ['127.0.0.1', '192.0.2.9', '2001:db8::9']) {
        const data = orbit(); Object.assign(data, {transport, clientExport: {address}});
        const ctx = fixture('orbit', data);
        ctx.location.hostname = address.includes(':') ? `[${address}]` : address;
        assert.equal(await ctx.settings.fillMissingModeDefaults({serverName: address}), true);
        assert.equal(ctx.settings.data.host, undefined);
        assert.equal(ctx.settings.data.clientExport.address, address);
        assert.equal(ctx.settings.data.clientExport.serverName, undefined);
        assert.equal(ctx.settings.toJson().clientExport.serverName, undefined);
        assert.equal(ctx.settings.data.path, '/core');
        assert.deepEqual(plain(ctx.settings.data.tls), data.tls);
        assert.equal(ctx.settings.clients[0].data.key, data.clients[0].key);
        assert.equal(ctx.settings.data.outerTls, undefined);
        ctx.settings.data.transport = 'tcp';
        assert.equal(ctx.settings.toJson().clientExport.serverName, undefined);
        assert.equal(ctx.settings.toJson().host, undefined);
    }
});

test('WebSocket generation ignores inferred names and retains explicit Host and peer fields', async () => {
    for (const transport of ['ws', 'wss']) {
        const data = orbit(); Object.assign(data, {transport, clientExport: {address: '192.0.2.9'}});
        const ctx = fixture('orbit', data);
        ctx.location.hostname = '127.0.0.1';
        assert.equal(await ctx.settings.fillMissingModeDefaults({serverName: 'custom.example'}), true);
        assert.equal(ctx.settings.data.host, undefined);
        assert.equal(ctx.settings.data.clientExport.serverName, undefined);
        ctx.settings.data.host = 'manual.example';
        ctx.settings.data.clientExport.serverName = 'inner.example';
        ctx.settings.data.path = '';
        assert.equal(await ctx.settings.fillMissingModeDefaults({serverName: 'replacement.example'}), true);
        assert.equal(ctx.settings.data.host, 'manual.example');
        assert.equal(ctx.settings.data.clientExport.serverName, 'inner.example');
        delete ctx.settings.data.host;
        assert.equal(await ctx.settings.fillMissingModeDefaults({serverName: 'replacement.example'}), true);
        assert.equal(ctx.settings.data.host, undefined);
    }
});

test('WebSocket Host validation matches the client DNS grammar without overwriting invalid manual hosts', async () => {
    const invalid = ['', '127.0.0.1', '[::1]', '2001:db8::1', 'vpn.example:443', 'vpn.example.', '.vpn.example', 'vpn..example', '-vpn.example', 'vpn-.example', '*.example', 'vpn_example', 'vpn example', 'éxample.test', 'a'.repeat(64)+'.test', ['a'.repeat(63),'b'.repeat(63),'c'.repeat(63),'d'.repeat(63)].join('.')];
    for (const host of invalid) {
        const data = orbit(); Object.assign(data, {transport: 'ws', host, path: '/core'});
        const ctx = fixture('orbit', data);
        assert.equal(ctx.NativeSettings.isOrbitDNSHost(host), false, host);
        assert.ok(ctx.settings.validationErrors.some(error => error.includes('WebSocket host')), host);
        if (host) {
            assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
            assert.equal(ctx.settings.data.host, host);
            assert.ok(ctx.settings.validationErrors.some(error => error.includes('WebSocket host')), host);
        }
    }
    for (const host of ['vpn.internal', 'EXAMPLE.test', 'a', 'a-b.c', 'a'.repeat(63)+'.test']) {
        const data = orbit(); Object.assign(data, {transport: 'ws', host});
        const ctx = fixture('orbit', data);
        assert.equal(ctx.NativeSettings.isOrbitDNSHost(host), true, host);
        assert.ok(!ctx.settings.validationErrors.some(error => error.includes('WebSocket host')), host);
    }
});

test('Existing WebSocket paths do not infer a missing peer or replace manual peer', async () => {
    const data = orbit(); Object.assign(data, {transport: 'ws', host: 'vpn.example', path: '/manual', clientExport: {address: '[2001:db8::5]'}});
    const ctx = fixture('orbit', data);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.data.clientExport.serverName, undefined);
    assert.equal(ctx.settings.data.clientExport.address, '[2001:db8::5]');
    assert.equal(ctx.settings.data.path, '/manual');
    ctx.settings.data.clientExport.serverName = 'my-inner.example';
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

for (const partial of [{certificate: cert}, {key}]) test(`WSS refuses a partial ${partial.key ? 'key' : 'certificate'} without changes`, async () => {
    const data = orbit(); Object.assign(data, {transport: 'wss', outerTls: partial});
    const ctx = fixture('orbit', data), before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('Reality requests missing X25519 material and preserves existing client keys and TLS', async () => {
    const data = orbit(); data.security = 'reality';
    const ctx = fixture('orbit', data);
    let request, calls = 0;
    ctx.NativeSettings.requestCredentials = async value => {calls++; request = plain(value); return {privateKey: 'B'.repeat(43), publicKey: 'C'.repeat(43), shortId: '0123456789abcdef', key: 'vck1_' + 'D'.repeat(86), target: 'must-not-insert.example:443', serverName: 'must-not-insert.example'};};
    const before = plain(ctx.settings.toJson());
    const originalTLS = plain(ctx.settings.data.tls);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.deepEqual(request, {kind: 'orbit-reality'});
    assert.deepEqual(plain(ctx.settings.data.reality), {privateKey: 'B'.repeat(43), shortIds: ['0123456789abcdef']});
    assert.deepEqual(plain(ctx.settings.data.tls), originalTLS);
    assert.equal(ctx.settings.toJson().tls, undefined);
    assert.deepEqual(plain(ctx.settings.toJson().clients), before.clients);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(calls, 1, 'missing deployment fields must not trigger repeated key generation');
    assert.equal(ctx.settings.data.reality.dest, undefined);
    assert.equal(ctx.settings.data.reality.serverNames, undefined);
    assert.ok(ctx.settings.validationErrors.length, 'missing deployment fields still require user input');
});

test('Orbit emits only active mode fields and restores dormant identities without rotation', () => {
    const data = orbit();
    Object.assign(data, {transport: 'wss', host: 'cover.example', path: '/existing', outerTls: {certificate: cert, key}, reality: {privateKey: 'B'.repeat(43), serverNames: ['cover.example'], shortIds: ['1234567890abcdef'], dest: 'cover.example:443'}, clientExport: {serverName: 'cover.example', address: '192.0.2.1'}});
    const ctx = fixture('orbit', data);
    const original = plain(ctx.settings.data);
    assert.equal(ctx.settings.toJson().reality, undefined);
    assert.deepEqual(plain(ctx.settings.toJson().outerTls), original.outerTls);
    ctx.settings.data.transport = 'ws';
    assert.equal(ctx.settings.toJson().outerTls, undefined);
    assert.equal(ctx.settings.toJson().host, original.host);
    for (const transport of ['tcp', 'quic']) {
        ctx.settings.data.transport = transport;
        const emitted = ctx.settings.toJson();
        for (const field of ['host', 'path', 'outerTls', 'reality']) assert.equal(emitted[field], undefined);
        assert.equal(emitted.clientExport.serverName, undefined);
        assert.equal(emitted.clientExport.address, '192.0.2.1');
        assert.deepEqual(plain(emitted.tls), original.tls);
    }
    ctx.settings.data.transport = 'tcp';
    ctx.settings.data.security = 'reality';
    assert.equal(ctx.settings.toJson().tls, undefined);
    assert.deepEqual(plain(ctx.settings.toJson().reality), original.reality);
    ctx.settings.data.security = '';
    assert.equal(ctx.settings.toJson().reality, undefined);
    assert.deepEqual(plain(ctx.settings.toJson().tls), original.tls);
    ctx.settings.data.security = 'reality';
    assert.deepEqual(plain(ctx.settings.toJson().reality), original.reality);
    ctx.settings.data.security = '';
    ctx.settings.data.transport = 'wss';
    assert.deepEqual(plain(ctx.settings.toJson().outerTls), original.outerTls);
    assert.equal(ctx.settings.toJson().host, original.host);
    assert.equal(ctx.settings.toJson().path, original.path);
    assert.equal(ctx.settings.toJson().clientExport.serverName, original.clientExport.serverName);
    assert.deepEqual(plain(ctx.settings.data.tls), original.tls);
    assert.deepEqual(plain(ctx.settings.data.reality), original.reality);
});

test('Reality existing private key is never rotated; missing short ID is securely filled', async () => {
    const data = orbit(); data.security = 'reality'; data.reality = {privateKey: 'existing-private', dest: 'own.example:443', serverNames: ['own.example'], custom: 3};
    const ctx = fixture('orbit', data);
    ctx.NativeSettings.requestCredentials = async () => {throw new Error('must not rotate existing key');};
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.data.reality.privateKey, 'existing-private');
    assert.equal(ctx.settings.data.reality.dest, 'own.example:443');
    assert.deepEqual(plain(ctx.settings.data.reality.serverNames), ['own.example']);
    assert.match(ctx.settings.data.reality.shortIds[0], /^[0-9a-f]{16}$/);
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('Reality generation failure/malformed result is atomic', async () => {
    for (const mode of ['http', 'invalid']) {
        const data = orbit(); data.security = 'reality';
        const ctx = fixture('orbit', data);
        ctx.NativeSettings.requestCredentials = async () => {if (mode === 'http') throw new Error('fixture failure'); return {privateKey: 'bad'};};
        const before = plain(ctx.settings.toJson());
        assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
        assert.deepEqual(plain(ctx.settings.toJson()), before);
    }
});

test('DNSTT switches both ways with dormant credentials restored and no mixed runtime auth', async () => {
    const ctx = fixture('dnstt', dnstt());
    ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    const client = ctx.settings.clients[0], secret = client.data.password;
    assert.equal(client.data.username, client.email);
    assert.equal(client.data.id, undefined);
    assert.match(secret, /^[0-9a-f-]{36}$/);
    ctx.settings.data.inner.protocol = 'vless';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(client.data.id, uuid);
    assert.equal(client.data.username, undefined);
    assert.equal(client.data.password, undefined);
    ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(client.data.password, secret);
    assert.equal(client.data.custom, 'keep');
    assert.equal(client.data.level, 2);
});

test('DNSTT preserves imported SOCKS credentials across VLESS mode', async () => {
    const data = dnstt(); data.inner.protocol = 'socks'; delete data.clients[0].id;
    Object.assign(data.clients[0], {username: 'manual-name', password: 'manual-password'});
    const ctx = fixture('dnstt', data);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    ctx.settings.data.inner.protocol = 'vless';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    const generated = ctx.settings.clients[0].data.id;
    assert.notEqual(generated, uuid);
    ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.clients[0].data.username, 'manual-name');
    assert.equal(ctx.settings.clients[0].data.password, 'manual-password');
});

test('DNSTT secure-entropy failure never removes the current UUID', async () => {
    const ctx = fixture('dnstt', dnstt()); ctx.settings.data.inner.protocol = 'socks'; ctx.crypto = undefined;
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('OpenVPN fills absent proofs only and preserves every existing credential', async () => {
    const existingProof = {keyId: 'existing-proof', key: 'ab'.repeat(32), future: 'keep'};
    const ctx = fixture('openvpn', openvpn([{email: 'old', commonName: 'old-cn', clientProof: existingProof}, {email: 'new', commonName: 'new-cn', clientProof: {future: 'retained'}}]));
    let count = 0;
    ctx.NativeSettings.requestCredentials = async request => {assert.deepEqual(plain(request), {kind: 'openvpn-proof'}); count++; return {keyId: 'issued-proof', key: 'cd'.repeat(32)};};
    const old = plain(ctx.settings.clients[0].toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(count, 1);
    assert.deepEqual(plain(ctx.settings.clients[0].toJson()), old);
    assert.deepEqual(plain(ctx.settings.clients[1].data.clientProof), {future: 'retained', keyId: 'issued-proof', key: 'cd'.repeat(32)});
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(count, 1);
});

for (const partial of [{keyId: 'manual'}, {key: 'ab'.repeat(32)}, {keyId: 'manual', key: 'bad'}, null]) test(`OpenVPN refuses partial/invalid proof ${JSON.stringify(partial)}`, async () => {
    const ctx = fixture('openvpn', openvpn([{email: 'new', commonName: 'new'}, {email: 'partial', commonName: 'partial', clientProof: partial}]));
    let calls = 0;
    ctx.NativeSettings.requestCredentials = async () => {calls++; throw new Error('must validate first');};
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.equal(calls, 0);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('OpenVPN multi-client generation rolls back all generated results if any request fails', async () => {
    const ctx = fixture('openvpn', openvpn([{email: 'a', commonName: 'a'}, {email: 'b', commonName: 'b'}]));
    let calls = 0;
    ctx.NativeSettings.requestCredentials = async () => {if (++calls === 2) throw new Error('second request failed'); return {keyId: 'first', key: 'ab'.repeat(32)};};
    const before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.equal(calls, 2);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
});

test('async mode changes reject stale writes and duplicate clicks', async () => {
    const data = orbit(); data.security = 'reality';
    const ctx = fixture('orbit', data);
    let resolve, calls = 0;
    ctx.NativeSettings.requestCredentials = () => {calls++; return new Promise(done => {resolve = done;});};
    const pending = ctx.settings.fillMissingModeDefaults();
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.equal(calls, 1);
    ctx.settings.data.reality = {privateKey: 'manual-edit'};
    resolve({privateKey: 'B'.repeat(43), publicKey: 'C'.repeat(43), shortId: '0123456789abcdef'});
    assert.equal(await pending, false);
    assert.deepEqual(plain(ctx.settings.data.reality), {privateKey: 'manual-edit'});
    assert.equal(ctx.settings.generating, false);
});

test('unrelated protocols and proof-off state remain identical', async () => {
    for (const protocol of ['anytls', 'mieru', 'openvpn']) {
        const ctx = fixture(protocol, {future: 'unchanged', clients: [{email: 'client', password: 'secret', commonName: 'name'}]});
        ctx.NativeSettings.requestCredentials = async () => {throw new Error('unexpected endpoint call');};
        const before = plain(ctx.settings.toJson());
        assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
        assert.deepEqual(plain(ctx.settings.toJson()), before);
    }
});

function shadowTLS() {
    return {version: 3, handshake: {address: 'tls.example', port: 443}, clients: [{email: 'a', password: 'outer-a'}, {email: 'b', password: 'outer-b'}], inner: {protocol: 'shadowsocks', settings: {network: 'tcp', method: '2022-blake3-aes-256-gcm', password: Buffer.alloc(32, 1).toString('base64'), custom: 'retained', clients: [{email: 'a', password: Buffer.alloc(32, 2).toString('base64')}, {email: 'b', password: Buffer.alloc(32, 3).toString('base64')}]}}};
}

test('ShadowTLS switches SOCKS/VLESS/SS2022 and restores original server and client keys', async () => {
    const ctx = fixture('shadowtls', shadowTLS());
    const initial = plain(ctx.settings.data.inner);
    const outer = ctx.settings.clients.map(client => client.data.password);
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true, ctx.settings.generationError);
    const socks = plain(ctx.settings.data.inner);
    assert.deepEqual(socks.settings.accounts.map(account => account.user), ['a', 'b']);
    assert.ok(socks.settings.accounts.every(account => account.pass));
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'vless';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true, ctx.settings.generationError);
    const vless = plain(ctx.settings.data.inner);
    assert.equal(vless.settings.decryption, 'none');
    assert.deepEqual(vless.settings.clients.map(client => client.email), ['a', 'b']);
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'shadowsocks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true, ctx.settings.generationError);
    assert.deepEqual(plain(ctx.settings.data.inner), initial);
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.deepEqual(plain(ctx.settings.data.inner), socks);
    assert.deepEqual(ctx.settings.clients.map(client => client.data.password), outer);
});

test('ShadowTLS cached mode gains only accounts for newly added users', async () => {
    const ctx = fixture('shadowtls', shadowTLS());
    const original = plain(ctx.settings.data.inner);
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'socks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    const fresh = ctx.settings.newClient(); fresh.email = 'third'; fresh.data.password = 'outer-third'; ctx.settings.clients.push(fresh);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    ctx.settings.rememberModeDefaults(); ctx.settings.data.inner.protocol = 'shadowsocks';
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.data.inner.settings.password, original.settings.password);
    assert.deepEqual(plain(ctx.settings.data.inner.settings.clients.slice(0, 2)), original.settings.clients);
    const added = ctx.settings.data.inner.settings.clients[2];
    assert.equal(added.email, 'third');
    assert.equal(Buffer.from(added.password, 'base64').length, 32);
});

test('ShadowTLS fills missing v2 and v3 passwords without rotating existing ones', async () => {
    const data = shadowTLS(); data.version = 2;
    const ctx = fixture('shadowtls', data);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    const generated = ctx.settings.data.password;
    assert.match(generated, /^[0-9a-f-]{36}$/);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.data.password, generated);
    ctx.settings.data.version = 3; delete ctx.settings.clients[1].data.password;
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(ctx.settings.clients[0].data.password, 'outer-a');
    assert.match(ctx.settings.clients[1].data.password, /^[0-9a-f-]{36}$/);
});

test('ShadowTLS same-mode partial keys are never overwritten and failed switches preserve live data', async () => {
    const data = shadowTLS(); delete data.inner.settings.password;
    const ctx = fixture('shadowtls', data), before = plain(ctx.settings.toJson());
    assert.equal(await ctx.settings.fillMissingModeDefaults(), false);
    assert.deepEqual(plain(ctx.settings.toJson()), before);
    const complete = fixture('shadowtls', shadowTLS());
    complete.settings.rememberModeDefaults(); complete.settings.data.inner.protocol = 'vless'; complete.crypto = undefined;
    const switched = plain(complete.settings.toJson());
    assert.equal(await complete.settings.fillMissingModeDefaults(), false);
    assert.deepEqual(plain(complete.settings.toJson()), switched);
});

test('external blanks cause no busy state and WSS ignores obsolete hostname inference option', async () => {
    const ctx = fixture('orbit', orbit());
    let writes = 0;
    Object.defineProperty(ctx.settings, 'generating', {get: () => false, set: () => {writes++;}});
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.equal(writes, 0);
    const data = orbit(); data.transport = 'wss';
    const wss = fixture('orbit', data);
    assert.equal(await wss.settings.fillMissingModeDefaults({serverName: 'explicit.example'}), true);
    assert.equal(wss.settings.data.host, undefined);
    assert.equal(wss.settings.data.path, '/core');
    let repeatedWrites = 0;
    Object.defineProperty(wss.settings, 'generating', {get: () => false, set: () => {repeatedWrites++;}});
    assert.equal(await wss.settings.fillMissingModeDefaults(), true);
    assert.equal(repeatedWrites, 0, 'a missing external Host must not repeat the local-path fill');
});

test('DNSTT account generation succeeds while domain and resolvers remain blank', async () => {
    const data = dnstt(); data.domain = ''; data.inner.protocol = 'socks'; data.clientExport = {resolvers: []};
    const ctx = fixture('dnstt', data);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.ok(ctx.settings.clients[0].data.password);
    assert.equal(ctx.settings.clients[0].data.username, ctx.settings.clients[0].email);
    assert.equal(ctx.settings.data.domain, '');
    assert.deepEqual(plain(ctx.settings.data.clientExport), {resolvers: []});
    assert.equal(ctx.settings.data.privateKey, data.privateKey);
    assert.ok(ctx.settings.validationErrors.some(error => /DNS tunnel|domain/i.test(error)));
});

test('ShadowTLS credentials generate without inserting a blank handshake cover or TLS name', async () => {
    const data = shadowTLS(); data.version = 2; data.handshake.address = ''; data.clientExport = {serverName: ''};
    const ctx = fixture('shadowtls', data);
    assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
    assert.match(ctx.settings.data.password, /^[0-9a-f-]{36}$/);
    assert.deepEqual(plain(ctx.settings.data.handshake), data.handshake);
    assert.deepEqual(plain(ctx.settings.data.clientExport), data.clientExport);
    assert.ok(ctx.settings.validationErrors.some(error => /handshake target/i.test(error)));
});

test('Reality preserves explicit blank deployment fields and existing supplied deployment values', async () => {
    for (const external of [{serverNames: [], dest: ''}, {serverNames: ['manual.example'], dest: 'manual.example:8443'}]) {
        const data = orbit(); data.security = 'reality'; data.reality = {...external, privateKey: 'existing-private'};
        data.clientExport = {address: '', serverName: '', resolvers: []};
        const ctx = fixture('orbit', data);
        assert.equal(await ctx.settings.fillMissingModeDefaults(), true);
        assert.deepEqual(plain(ctx.settings.data.reality.serverNames), external.serverNames);
        assert.equal(ctx.settings.data.reality.dest, external.dest);
        assert.deepEqual(plain(ctx.settings.data.clientExport), data.clientExport);
        assert.equal(ctx.settings.data.reality.privateKey, 'existing-private');
        assert.match(ctx.settings.data.reality.shortIds[0], /^[0-9a-f]{16}$/);
    }
});

test('async generation preserves edits to dormant fields excluded from active runtime JSON', async () => {
    const data = orbit(); data.security = 'reality';
    const ctx = fixture('orbit', data);
    let resolve;
    ctx.NativeSettings.requestCredentials = () => new Promise(done => {resolve = done;});
    const pending = ctx.settings.fillMissingModeDefaults();
    ctx.settings.data.tls.key = ['manual-dormant-key-edit'];
    resolve({privateKey: 'B'.repeat(43), publicKey: 'C'.repeat(43), shortId: '0123456789abcdef'});
    assert.equal(await pending, false);
    assert.deepEqual(plain(ctx.settings.data.tls.key), ['manual-dormant-key-edit']);
    assert.equal(ctx.settings.data.reality, undefined);
});
