'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const context = vm.createContext({console, URL, URLSearchParams, TextEncoder, TextDecoder});
vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/util/index.js'), 'utf8'), context);
vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model/outbound.js'), 'utf8') + '\nglobalThis.models = {Outbound, Protocols};', context);
const {Outbound, Protocols} = context.models;
const clean = value => JSON.parse(JSON.stringify(value));
const roundTrip = json => clean(Outbound.fromJson(json).toJson());
const uuid = '40ab8f72-44ee-4e7d-984c-c5633ec89fe1';
const publicKey = '12'.repeat(32);
const settings = {
    orbit: {address: '127.0.0.1', port: 1443, key: 'test-fixture-key', transport: 'tcp', handshakeTimeout: 15, resolver: '127.0.0.1:5353'},
    dnstt: {domain: 'tunnel.example.test', publicKey, resolvers: [{transport: 'udp', address: '127.0.0.1:5353'}], inner: {protocol: 'vless', uuid}},
    openvpn: {server: {address: '127.0.0.1', port: 1194, network: 'tcp'}, certificates: {ca: 'CA\nPEM', cert: 'CERT\nPEM', key: 'KEY\nPEM'}, advanced: {dev: 'tun', nobind: true, remoteCertTls: 'server', mtu: 1400}},
    anytls: {address: '127.0.0.1', port: 1443, password: 'fixture-password', tlsSettings: {serverName: 'localhost', allowInsecure: false, certificates: [{certificate: ['CA', 'PEM']}]}},
    shadowtls: {address: '127.0.0.1', port: 1443, password: uuid, version: 3, serverName: 'localhost', strict: false, uuidSessionId: true},
    mieru: {address: '127.0.0.1', port: 1443, username: uuid, password: 'fixture-password', transport: 'udp', uuidMetadataTrailer: true},
};

for (const [protocol, data] of Object.entries(settings)) {
    test(protocol + ': preserves all nested settings and outbound chaining on import/edit/export', () => {
        const input = {tag: protocol + '-test', protocol, settings: {...data, futureOption: {nested: ['keep', {flag: false}]}}, proxySettings: {tag: 'carrier', transportLayer: true}, targetStrategy: 'UseIPv4', streamSettings: {sockopt: {tcpFastOpen: false, mark: 7}}};
        const model = Outbound.fromJson(input);
        assert.equal(model.isNative, true);
        assert.equal(model.canEnableStream(), false);
        assert.equal(model.canEnableTls(), false);
        assert.equal(model.canEnableMux(), false);
        assert.deepEqual(clean(model.settings.validationErrors), []);
        const output = clean(model.toJson());
        assert.deepEqual(output.settings, input.settings);
        assert.deepEqual(output.proxySettings, input.proxySettings);
        assert.equal(output.targetStrategy, input.targetStrategy);
        assert.equal(output.streamSettings.sockopt.mark, 7);
        assert.equal(output.streamSettings.sockopt.tcpFastOpen, false);
        model.settings.write(protocol === 'dnstt' ? 'domain' : protocol === 'openvpn' ? 'server.address' : 'address', protocol === 'dnstt' ? 'changed.example.test' : '127.0.0.2');
        assert.deepEqual(clean(model.toJson()).settings.futureOption, input.settings.futureOption);
        assert.deepEqual(clean(model.settings.validationErrors), []);
    });
    test(protocol + ': new settings omit compatibility flags and never add outer TLS', () => {
        const model = new Outbound('test', protocol);
        const output = clean(model.toJson());
        assert.equal(output.streamSettings, undefined);
        assert.equal(output.settings.uuidHashMiddle, undefined);
        assert.equal(output.settings.uuidSessionId, undefined);
        assert.equal(output.settings.uuidMetadataTrailer, undefined);
        assert.equal(output.settings.clientProof, undefined);
        assert.ok(model.settings.validationErrors.length > 0, 'Incomplete new connections must not be submitted.');
    });
}

test('native settings clone the input and cannot mutate caller configuration', () => {
    const input = {protocol: 'anytls', settings: clean(settings.anytls)};
    const model = Outbound.fromJson(input);
    model.settings.write('tlsSettings.serverName', 'edited.example.test');
    assert.equal(input.settings.tlsSettings.serverName, 'localhost');
    const output = model.settings.toJson();
    output.tlsSettings.serverName = 'other.example.test';
    assert.equal(model.settings.read('tlsSettings.serverName'), 'edited.example.test');
});

test('native setters reject prototype traversal', () => {
    const model = new Outbound.NativeSettings('anytls', settings.anytls);
    for (const key of ['__proto__.polluted', 'constructor.prototype.polluted', 'tlsSettings.__proto__.polluted']) assert.throws(() => model.write(key, true), /Invalid settings path/);
    assert.equal({}.polluted, undefined);
});

test('imported unknown dangerous-looking keys remain plain JSON data', () => {
    const raw = JSON.parse('{"address":"127.0.0.1","port":443,"password":"fixture","__proto__":{"polluted":true}}');
    const model = new Outbound.NativeSettings('anytls', raw);
    assert.deepEqual(clean(model.toJson()), raw);
    assert.equal({}.polluted, undefined);
});

test('stock DNS serialization remains unchanged', () => {
    const input = {protocol: 'dns', settings: {network: 'udp', address: '127.0.0.1', port: 53, nonIPQuery: 'reject', blockTypes: [28]}};
    const model = Outbound.fromJson(input);
    assert.equal(model.isNative, false);
    assert.deepEqual(roundTrip(input), input);
});

test('DNS tunnel canonical envelope and direct dnstt alias both round-trip', () => {
    const canonical = {protocol: 'dns', settings: {tunnel: settings.dnstt, futureEnvelope: {keep: true}}};
    assert.deepEqual(roundTrip(canonical), canonical);
    assert.equal(Outbound.fromJson(canonical).hasAddressPort(), false);
    assert.deepEqual(roundTrip({protocol: 'dnstt', settings: settings.dnstt}), {protocol: 'dnstt', settings: settings.dnstt});
});

test('DNS tunnel resolver editor preserves nested values and rejects invalid limits', () => {
    const model = new Outbound.NativeSettings('dnstt', settings.dnstt);
    model.addResolver();
    model.write('resolvers.1.address', 'https://resolver.example.test/dns-query');
    model.write('resolvers.1.transport', 'doh');
    model.write('resolvers.1.bootstrap', '192.0.2.10');
    model.write('resolvers.1.caPem', 'CA\nPEM');
    assert.deepEqual(clean(model.validationErrors), []);
    model.write('maxConcurrentQueries', 257);
    assert.match(model.validationErrors.join(' '), /maxConcurrentQueries/);
    model.write('maxConcurrentQueries', 32);
    model.write('labelMin', 63); model.write('labelMax', 62);
    assert.match(model.validationErrors.join(' '), /Minimum label/);
    model.removeResolver(0);
    assert.equal(model.resolvers.length, 1);
    assert.equal(model.resolvers[0].caPem, 'CA\nPEM');
});

test('DNS tunnel malformed key, resolver and inner UUID are rejected without rewriting', () => {
    const bad = {...settings.dnstt, publicKey: '0'.repeat(64), resolvers: [null], inner: {protocol: 'vless', uuid: 'invalid'}};
    const model = new Outbound.NativeSettings('dnstt', bad);
    assert.ok(model.validationErrors.length >= 3);
    assert.deepEqual(clean(model.toJson()), bad);
});

test('OpenVPN inline line arrays and base64 are retained without structured defaults', () => {
    for (const input of [{ovpn: ['client', 'proto tcp', '<ca>', 'CA', '</ca>'], username: 'fixture'}, {ovpnBase64: 'Y2xpZW50Cg==', mtu: 1400}]) {
        const model = new Outbound.NativeSettings('openvpn', input);
        assert.deepEqual(clean(model.toJson()), input);
        assert.deepEqual(clean(model.validationErrors), []);
        assert.equal(model.read('server'), undefined);
    }
    assert.deepEqual(roundTrip({protocol: 'ov', settings: {ovpn: 'client\n'}}), {protocol: 'ov', settings: {ovpn: 'client\n'}});
});

test('OpenVPN format switch retains proof and removes conflicting wrappers', () => {
    const model = new Outbound.NativeSettings('openvpn', {...settings.openvpn, clientProof: {keyId: 'fixture', key: 'ab'.repeat(32)}});
    model.changeInputMode('text'); model.write('ovpn', 'client\n');
    assert.equal(model.read('server'), undefined);
    assert.equal(model.read('certificates'), undefined);
    assert.equal(model.read('clientProof.keyId'), 'fixture');
    assert.deepEqual(clean(model.validationErrors), []);
    model.changeInputMode('base64'); model.write('ovpnBase64', 'Y2xpZW50Cg==');
    assert.equal(model.read('ovpn'), undefined);
    assert.deepEqual(clean(model.validationErrors), []);
});

test('OpenVPN proof enforces exclusive source, boolean absence and exact key size', () => {
    const model = new Outbound.NativeSettings('openvpn', settings.openvpn);
    model.setProofEnabled(true); model.write('clientProof.keyId', 'fixture'); model.write('clientProof.key', 'ab'.repeat(32));
    assert.deepEqual(clean(model.validationErrors), []);
    model.write('clientProof.keyFile', '/private/proof.key');
    assert.match(model.validationErrors.join(' '), /exactly one/);
    model.setProofKeyMode('keyFile'); model.write('clientProof.keyFile', '/private/proof.key');
    assert.equal(model.read('clientProof.key'), undefined);
    assert.deepEqual(clean(model.validationErrors), []);
    model.setProofKeyMode('key'); model.write('clientProof.key', 'short');
    assert.match(model.validationErrors.join(' '), /64 hexadecimal/);
    model.setProofEnabled(false);
    assert.equal(model.toJson().clientProof, undefined);
});

test('OpenVPN multiple wrappers and null proof are not silently repaired', () => {
    for (const extra of [{ovpn: 'client\n'}, {clientProof: null}]) {
        const input = {...settings.openvpn, ...extra};
        const model = new Outbound.NativeSettings('openvpn', input);
        assert.ok(model.validationErrors.length);
        assert.deepEqual(clean(model.toJson()), input);
    }
});

test('Orbit link import preserves link, options and does not add conflicting endpoint', () => {
    const input = {link: 'orbit://test-fixture', handshakeTimeout: 30, resolver: '127.0.0.1:5353'};
    const model = new Outbound.NativeSettings('orbit', input);
    assert.equal(model.inputMode, 'link');
    assert.deepEqual(clean(model.validationErrors), []);
    assert.deepEqual(clean(model.toJson()), input);
    model.write('port', 443);
    assert.match(model.validationErrors.join(' '), /not both/);
    model.changeInputMode('fields');
    assert.equal(model.read('link'), undefined);
    assert.equal(model.read('resolver'), input.resolver);
});

test('Orbit Reality fields are retained and rejected on the wrong carrier', () => {
    const input = {...settings.orbit, security: 'reality', reality: {serverName: 'localhost', publicKey, shortId: '1234', fingerprint: 'chrome'}};
    const model = new Outbound.NativeSettings('orbit', input);
    assert.deepEqual(clean(model.validationErrors), []);
    model.write('transport', 'quic');
    assert.match(model.validationErrors.join(' '), /TCP carrier/);
    assert.deepEqual(clean(model.toJson()).reality, input.reality);
});

test('ShadowTLS custom auth requires v3 UUID and strict false is retained', () => {
    const model = new Outbound.NativeSettings('shadowtls', settings.shadowtls);
    assert.deepEqual(clean(model.validationErrors), []);
    assert.equal(model.toJson().strict, false);
    model.write('version', 2);
    assert.match(model.validationErrors.join(' '), /version 3/);
    model.write('version', 3); model.write('password', 'not-a-uuid');
    assert.match(model.validationErrors.join(' '), /must be a UUID/);
});

test('Mieru UUID custom auth and length bounds are validated', () => {
    const model = new Outbound.NativeSettings('mieru', settings.mieru);
    model.write('username', 'not-a-uuid');
    assert.match(model.validationErrors.join(' '), /UUID/);
    model.write('username', uuid); model.write('password', 'x'.repeat(4097));
    assert.match(model.validationErrors.join(' '), /length/);
});

test('native false compatibility flags can be removed without touching other data', () => {
    const model = new Outbound.NativeSettings('anytls', {...settings.anytls, uuidHashMiddle: true});
    const field = model.fields.find(field => field.path === 'uuidHashMiddle');
    model.setField(field, false);
    assert.equal(model.toJson().uuidHashMiddle, undefined);
    assert.deepEqual(clean(model.toJson()).tlsSettings, settings.anytls.tlsSettings);
    model.setField(field, true);
    assert.equal(model.toJson().uuidHashMiddle, true);
});

test('malformed auth types remain invalid rather than changing server compatibility', () => {
    for (const [protocol, key] of [['anytls', 'uuidHashMiddle'], ['shadowtls', 'uuidSessionId'], ['mieru', 'uuidMetadataTrailer']]) {
        for (const bad of ['false', 1, null, {}]) {
            const model = new Outbound.NativeSettings(protocol, {...settings[protocol], [key]: bad});
            assert.match(model.validationErrors.join(' '), /boolean/);
            assert.deepEqual(clean(model.toJson())[key], bad);
        }
    }
});

test('VMess raw UUID flag imports canonical and flat forms and omits ordinary false', () => {
    const base = {vnext: [{address: '127.0.0.1', port: 443, users: [{id: uuid, security: 'auto'}]}]};
    assert.deepEqual(clean(Outbound.VmessSettings.fromJson(base).toJson()), base);
    const canonical = clean(base); canonical.vnext[0].users[0].rawUuidAuth = true;
    assert.deepEqual(clean(Outbound.VmessSettings.fromJson(canonical).toJson()), canonical);
    const flat = Outbound.VmessSettings.fromJson({...base, rawUuidAuth: true});
    assert.equal(flat.toJson().vnext[0].users[0].rawUuidAuth, true);
    flat.rawUuidAuth = false;
    assert.deepEqual(clean(flat.toJson()), base);
    for (const bad of ['false', null, {}]) {
        flat.rawUuidAuth = bad;
        assert.ok(flat.validationErrors.length);
        assert.deepEqual(clean(flat.toJson()).vnext[0].users[0].rawUuidAuth, bad);
    }
});

test('Trojan UUID hash flag imports canonical and flat forms and omits ordinary false', () => {
    const base = {servers: [{address: '127.0.0.1', port: 443, password: uuid}]};
    assert.deepEqual(clean(Outbound.TrojanSettings.fromJson(base).toJson()), base);
    const canonical = clean(base); canonical.servers[0].uuidHashPrefix = true;
    assert.deepEqual(clean(Outbound.TrojanSettings.fromJson(canonical).toJson()), canonical);
    const flat = Outbound.TrojanSettings.fromJson({...base, uuidHashPrefix: true});
    assert.equal(flat.toJson().servers[0].uuidHashPrefix, true);
    flat.uuidHashPrefix = false;
    assert.deepEqual(clean(flat.toJson()), base);
    for (const bad of ['false', null, {}]) {
        flat.uuidHashPrefix = bad;
        assert.ok(flat.validationErrors.length);
        assert.deepEqual(clean(flat.toJson()).servers[0].uuidHashPrefix, bad);
    }
});

test('switching protocol clears old native top-level carrier settings', () => {
    const model = Outbound.fromJson({protocol: 'shadowtls', settings: settings.shadowtls, proxySettings: {tag: 'old'}, mux: {enabled: true}, streamSettings: {security: 'tls'}});
    model.protocol = 'mieru';
    const output = clean(model.toJson());
    assert.equal(output.proxySettings, undefined);
    assert.equal(output.streamSettings, undefined);
    assert.equal(output.mux, undefined);
});

test('invalid native settings JSON remains visible to validation without being defaulted', () => {
    for (const data of [null, [], 'invalid', 9]) {
        const model = new Outbound.NativeSettings('anytls', data);
        assert.ok(model.validationErrors.length);
        assert.deepEqual(clean(model.toJson()), data);
    }
});

test('legacy inner SOCKS and VLESS preserve explicit ShadowTLS carrier chaining', () => {
    for (const config of [
        {protocol: 'socks', settings: {servers: [{address: '127.0.0.1', port: 1080, users: []}]}},
        {protocol: 'vless', settings: {address: '127.0.0.1', port: 1443, id: uuid, encryption: 'none'}},
    ]) {
        const stock = Outbound.fromJson(config);
        const ordinary = clean(stock.toJson());
        assert.equal(ordinary.proxySettings, undefined);
        const chain = {tag: 'shadowtls-carrier', transportLayer: true, futureOption: 'retained'};
        const model = Outbound.fromJson({...config, proxySettings: chain});
        assert.deepEqual(clean(model.toJson()).proxySettings, chain);
        assert.deepEqual(clean(model.validationErrors), []);
        model.setChainingEnabled(false);
        assert.deepEqual(clean(model.toJson()), ordinary);
        model.setChainingEnabled(true);
        assert.match(model.validationErrors.join(' '), /carrier outbound tag/);
        model.proxySettings.tag = 'shadowtls-carrier';
        assert.deepEqual(clean(model.validationErrors), []);
    }
});

test('invalid outbound chaining stays invalid and never silently becomes direct', () => {
    for (const proxySettings of [null, 'bad', {tag: ''}, {tag: 'self'}, {tag: 'carrier', transportLayer: 'true'}]) {
        const model = Outbound.fromJson({tag: 'self', protocol: 'anytls', settings: settings.anytls, proxySettings});
        assert.ok(model.validationErrors.length);
        assert.deepEqual(clean(model.toJson()).proxySettings, proxySettings);
    }
});

test('Orbit timeout bound matches the core and AnyTLS retains uint32 timeout settings', () => {
    const orbit = new Outbound.NativeSettings('orbit', {...settings.orbit, handshakeTimeout: 91});
    assert.match(orbit.validationErrors.join(' '), /handshakeTimeout/);
    const anytls = new Outbound.NativeSettings('anytls', {...settings.anytls, handshakeTimeout: 301});
    assert.deepEqual(clean(anytls.validationErrors), []);
    const fractional = new Outbound.NativeSettings('anytls', {...settings.anytls, idleSessionTimeout: 1.5});
    assert.match(fractional.validationErrors.join(' '), /idleSessionTimeout/);
    const huge = new Outbound.NativeSettings('anytls', {...settings.anytls, idleSessionCheckInterval: 99999999999});
    assert.match(huge.validationErrors.join(' '), /idleSessionCheckInterval/);
    const negative = new Outbound.NativeSettings('anytls', {...settings.anytls, minIdleSession: -1});
    assert.match(negative.validationErrors.join(' '), /minIdleSession/);
    const okIdle = new Outbound.NativeSettings('anytls', {...settings.anytls, idleSessionCheckInterval: 30, idleSessionTimeout: 300, minIdleSession: 5});
    assert.deepEqual(clean(okIdle.validationErrors), []);
});


test('SS2022 UUID identity import is optional, explicit and preserves malformed values', () => {
    for (const method of ['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305']) {
        const base={servers:[{address:'127.0.0.1',port:443,password:'c3ludGhldGlj:'+uuid,method}]};
        const stock=Outbound.ShadowsocksSettings.fromJson(base);
        assert.equal(Object.hasOwn(clean(stock.toJson()).servers[0],'uuidIdentityKeys'),false);
        const enabled=Outbound.ShadowsocksSettings.fromJson({servers:[{...base.servers[0],uuidIdentityKeys:true}]});
        assert.equal(clean(enabled.toJson()).servers[0].uuidIdentityKeys,true);
        assert.deepEqual(clean(enabled.validationErrors),[]);
        enabled.method='aes-256-gcm';
        assert.match(enabled.validationErrors.join(' '),/SS2022/);
        for(const value of [null,'true',1,{}]) {
            enabled.uuidIdentityKeys=value;
            assert.ok(enabled.validationErrors.length);
            assert.deepEqual(clean(enabled.toJson()).servers[0].uuidIdentityKeys,value);
        }
    }
});

test('Orbit QUIC warning is explicit and TCP remains the default', () => {
    const defaults=new Outbound.NativeSettings('orbit');
    assert.equal(defaults.read('transport'),'tcp');
    assert.doesNotMatch(defaults.help,/passive network observer/);
    defaults.write('transport','quic');
    assert.match(defaults.help,/passive network observer/);
});


test('OpenVPN tls-auth direction can return to omitted bidirectional default', () => {
    const model=new Outbound.NativeSettings('openvpn',settings.openvpn);
    const field=model.fields.find(field=>field.path==='certificates.keyDirection');
    assert.equal(model.read('certificates.keyDirection'),undefined);
    model.setField(field,0);
    assert.equal(model.toJson().certificates.keyDirection,0);
    model.setField(field,'');
    assert.equal(Object.hasOwn(model.toJson().certificates,'keyDirection'),false);
});


test('Orbit complete-link QUIC mode shows the same warning', () => {
    const model=new Outbound.NativeSettings('orbit',{link:'orbit://192.0.2.1:8443@vck1_'+'A'.repeat(86)+'&transport=%71uic#synthetic'});
    assert.equal(model.hasQuicWarning,true);
    assert.match(model.help,/passive network observer/);
    model.write('link','core://192.0.2.1:8443@vck1_'+'A'.repeat(86)+'&transport=tcp');
    assert.equal(model.hasQuicWarning,false);
});
