'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const UUID = '00112233-4455-4677-8899-aabbccddeeff';
const RAW_UUID = Buffer.from(UUID.replaceAll('-', ''), 'hex');
const SERVER_PSK = 'ICAgICAgICAgICAgICAgIA==';
const USER_PSK = 'QEBAQEBAQEBAQEBAQEBAQA==';
let sequence = 0;
const context = vm.createContext({
    console, TextEncoder, URL, URLSearchParams,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    Base64: {encode: (value, urlSafe) => Buffer.from(value, 'utf8').toString(urlSafe ? 'base64url' : 'base64')},
    location: {hostname: 'panel.example'},
    ObjectUtil: {
        isEmpty: value => value === null || value === undefined || value === '',
        isArrEmpty: value => !value || !value.length,
        clone: value => value === undefined ? undefined : JSON.parse(JSON.stringify(value)),
        cloneProps: (target, source) => Object.assign(target, source),
    },
    RandomUtil: {
        randomUUID: () => '11111111-2222-4333-8444-' + String(++sequence).padStart(12, '0'),
        randomLowerAndNum: () => `synthetic${++sequence}`,
        randomSeq: () => `synthetic${++sequence}`,
        randomInteger: () => 18080,
        randomShortIds: () => ['1234567890abcdef'],
        randomShadowsocksPassword: () => 'synthetic-password',
    },
    Wireguard: {generateKeypair: () => ({publicKey: 'synthetic-public', privateKey: 'synthetic-private'})},
    NumberFormatter: {toFixed: (value, precision) => Number(value.toFixed(precision))},
    SizeFormatter: {ONE_GB: 1073741824},
});
vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model/inbound.js'), 'utf8') + '\nglobalThis.InboundModel = Inbound;', context);
const Inbound = context.InboundModel;

function fixture(protocol, clientOptions = {}, settingOptions = {}) {
    return Inbound.fromJson({
        protocol, port: 443, listen: '0.0.0.0',
        settings: {
            ...(protocol === 'shadowsocks' ? {method: '2022-blake3-aes-128-gcm', password: SERVER_PSK} : {}),
            ...settingOptions,
            clients: [{id: UUID, password: protocol === 'shadowsocks' ? USER_PSK : UUID, security: 'auto', email: 'selected@example.test', enable: true, ...clientOptions}],
        },
        streamSettings: {network: 'tcp', security: 'none', tcpSettings: {header: {type: 'none'}}},
    });
}

const share = model => model.genLink('vpn.example.test', 443, 'same', 'Synthetic fixture', model.clients[0]);
const vmessJSON = link => JSON.parse(Buffer.from(link.slice('vmess://'.length), 'base64').toString('utf8'));
function ssCredentials(link) {
    return Buffer.from(decodeURIComponent(new URL(link).username), 'base64url').toString('utf8').split(':');
}

// Captured by executing c02848d:web/assets/js/model/inbound.js with these exact
// synthetic inputs. Keep byte-for-byte comparisons independent of current code.
const ordinaryBaseline = {
    vmess: 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJTeW50aGV0aWMgZml4dHVyZSIsCiAgImFkZCI6ICJ2cG4uZXhhbXBsZS50ZXN0IiwKICAicG9ydCI6IDQ0MywKICAiaWQiOiAiMDAxMTIyMzMtNDQ1NS00Njc3LTg4OTktYWFiYmNjZGRlZWZmIiwKICAic2N5IjogImF1dG8iLAogICJuZXQiOiAidGNwIiwKICAidGxzIjogIm5vbmUiLAogICJ0eXBlIjogIm5vbmUiCn0=',
    trojan: 'trojan://00112233-4455-4677-8899-aabbccddeeff@vpn.example.test:443?type=tcp&security=none#Synthetic%20fixture',
    shadowsocks: 'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206SUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQT09OlFFQkFRRUJBUUVCQVFFQkFRRUJBUUE9PQ@vpn.example.test:443?type=tcp#Synthetic%20fixture',
};

for (const protocol of Object.keys(ordinaryBaseline)) {
    test(`${protocol}: ordinary share link remains byte-for-byte identical to baseline`, () => {
        assert.equal(share(fixture(protocol)), ordinaryBaseline[protocol]);
        const flags = {vmess: 'rawUuidAuth', trojan: 'uuidHashPrefix', shadowsocks: 'uuidIdentityKeys'};
        assert.equal(share(fixture(protocol, {[flags[protocol]]: false})), ordinaryBaseline[protocol]);
    });
}

test('VMess custom link carries the exact backend boolean and keeps ordinary fields', () => {
    const model = fixture('vmess', {rawUuidAuth: true});
    const before = JSON.stringify(model.toJson());
    assert.deepEqual(vmessJSON(share(model)), {...vmessJSON(ordinaryBaseline.vmess), rawUuidAuth: true});
    assert.equal(JSON.stringify(model.toJson()), before, 'export must not mutate account or transport settings');
    for (const flag of [undefined, false]) {
        assert.equal(Object.hasOwn(vmessJSON(share(fixture('vmess', {rawUuidAuth: flag}))), 'rawUuidAuth'), false);
    }
    for (const flag of ['true', 1, null]) {
        assert.throws(() => share(fixture('vmess', {rawUuidAuth: flag})), /boolean|JSON/i);
    }
});

test('Trojan custom link uses uuidHashPrefix=true without changing credentials', () => {
    const custom = new URL(share(fixture('trojan', {uuidHashPrefix: true})));
    assert.equal(custom.searchParams.get('uuidHashPrefix'), 'true');
    assert.equal(custom.username, UUID);
    custom.searchParams.delete('uuidHashPrefix');
    assert.equal(custom.toString(), ordinaryBaseline.trojan);
    for (const flag of [undefined, false]) {
        assert.equal(new URL(share(fixture('trojan', {uuidHashPrefix: flag}))).searchParams.has('uuidHashPrefix'), false);
    }
    for (const flag of ['true', 1, null]) {
        assert.throws(() => share(fixture('trojan', {uuidHashPrefix: flag})), /boolean|JSON/i);
    }
});

for (const [method, size] of [['2022-blake3-aes-128-gcm', 16], ['2022-blake3-aes-256-gcm', 32]]) {
    test(`${method}: UUID identity is binary base64 and server PSK is unchanged`, () => {
        const serverPSK = Buffer.alloc(size, 0x93).toString('base64');
        const model = fixture('shadowsocks', {password: UUID, uuidIdentityKeys: true}, {method, password: serverPSK});
        const before = JSON.stringify(model.toJson());
        const expected = (size === 16 ? RAW_UUID : Buffer.concat([RAW_UUID, RAW_UUID])).toString('base64');
        assert.deepEqual(ssCredentials(share(model)), [method, serverPSK, expected]);
        assert.equal(JSON.stringify(model.toJson()), before);
        assert.notEqual(expected, Buffer.from(UUID).toString('base64'), 'UUID text bytes are not the key bytes');
    });
}

test('SS2022 inherited opt-in honors a per-client false override', () => {
    const expected = RAW_UUID.toString('base64');
    const inherited = fixture('shadowsocks', {password: UUID}, {uuidIdentityKeys: true});
    assert.equal(ssCredentials(share(inherited))[2], expected);
    const explicitFalse = fixture('shadowsocks', {password: UUID, uuidIdentityKeys: false}, {uuidIdentityKeys: true});
    assert.equal(ssCredentials(share(explicitFalse))[2], UUID);
    const ordinary = fixture('shadowsocks', {password: UUID});
    assert.equal(ssCredentials(share(ordinary))[2], UUID, 'ordinary mode must not silently rewrite identity');
    const explicitTrue = fixture('shadowsocks', {password: UUID, uuidIdentityKeys: true}, {uuidIdentityKeys: false});
    assert.equal(ssCredentials(share(explicitTrue))[2], expected);
});

test('SS2022 already-canonical base64 identity is preserved even when opted in', () => {
    for (const [method, size] of [['2022-blake3-aes-128-gcm', 16], ['2022-blake3-aes-256-gcm', 32]]) {
        const identity = Buffer.alloc(size, 0xfb).toString('base64');
        const serverPSK = Buffer.alloc(size, 0xe1).toString('base64');
        assert.deepEqual(ssCredentials(share(fixture('shadowsocks', {password: identity, uuidIdentityKeys: true}, {method, password: serverPSK}))), [method, serverPSK, identity]);
    }
});

test('UUID parser forms match backend identity conversion, including legacy 38-byte wrapper', () => {
    const forms = [UUID, UUID.toUpperCase(), UUID.replaceAll('-', ''), `urn:uuid:${UUID}`, `URN:UUID:${UUID.toUpperCase()}`, `{${UUID}}`, `!${UUID}?`];
    for (const form of forms) {
        assert.equal(Inbound.normalizeSS2022IdentityKey('2022-blake3-aes-128-gcm', form), RAW_UUID.toString('base64'), form);
        assert.equal(Inbound.normalizeSS2022IdentityKey('2022-blake3-aes-256-gcm', form), Buffer.concat([RAW_UUID, RAW_UUID]).toString('base64'), form);
    }
    assert.equal(Inbound.normalizeSS2022IdentityKey('2022-blake3-chacha20-poly1305', UUID), Buffer.concat([RAW_UUID, RAW_UUID]).toString('base64'));
    for (const ordinary of ['not-a-uuid', '00'.repeat(17), USER_PSK]) {
        assert.equal(Inbound.normalizeSS2022IdentityKey('2022-blake3-aes-128-gcm', ordinary), ordinary);
    }
});

test('ChaCha single-user server PSK is never treated as an identity', () => {
    const password = Buffer.alloc(32, 0xfd).toString('base64');
    const model = fixture('shadowsocks', {}, {method: '2022-blake3-chacha20-poly1305', password, uuidIdentityKeys: true});
    assert.deepEqual(ssCredentials(model.genInboundLinks('Synthetic fixture')), ['2022-blake3-chacha20-poly1305', password]);
});

test('ordinary AEAD is unchanged and unsupported opted-in methods fail explicitly', () => {
    const method = 'aes-256-gcm';
    assert.deepEqual(ssCredentials(share(fixture('shadowsocks', {password: UUID}, {method}))), [method, UUID]);
    assert.throws(() => share(fixture('shadowsocks', {password: UUID, uuidIdentityKeys: true}, {method})), /JSON|supported|2022/i);
    assert.throws(() => Inbound.normalizeSS2022IdentityKey('toString', UUID), /JSON|supported|2022/i);
    for (const flag of ['true', 1, null]) {
        assert.throws(() => share(fixture('shadowsocks', {password: UUID, uuidIdentityKeys: flag})), /boolean|JSON/i);
        assert.throws(() => share(fixture('shadowsocks', {password: UUID}, {uuidIdentityKeys: flag})), /boolean|JSON/i);
    }
});

test('all-links and per-inbound exports retain custom authentication on each endpoint', () => {
    for (const [protocol, flag] of [['vmess', 'rawUuidAuth'], ['trojan', 'uuidHashPrefix']]) {
        const model = fixture(protocol, {[flag]: true});
        model.stream.externalProxy = [
            {dest: 'edge-one.example.test', port: 1443, forceTls: 'none', remark: 'one'},
            {dest: 'edge-two.example.test', port: 2443, forceTls: 'none', remark: 'two'},
        ];
        const links = model.genAllLinks('Synthetic fixture', '-ieo', model.clients[0]);
        assert.equal(links.length, 2);
        const all = model.genInboundLinks('Synthetic fixture', '-ieo').split('\r\n');
        assert.deepEqual(all, Array.from(links, item => item.link));
        for (const [index, item] of Array.from(links).entries()) {
            if (protocol === 'vmess') {
                const parsed = vmessJSON(item.link);
                assert.equal(parsed.rawUuidAuth, true);
                assert.equal(parsed.add, model.stream.externalProxy[index].dest);
            } else {
                const parsed = new URL(item.link);
                assert.equal(parsed.searchParams.get('uuidHashPrefix'), 'true');
                assert.equal(parsed.hostname, model.stream.externalProxy[index].dest);
            }
        }
    }
});
