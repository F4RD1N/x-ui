'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const input = {
  vmess: {clients: [{id: '11111111-2222-4333-8444-555555555555', email: 'legacy-vmess', security: 'auto', enable: true}]},
  vless: {clients: [{id: '11111111-2222-4333-8444-555555555555', email: 'legacy-vless', enable: true}], decryption: 'none', dialects: [120], minClientVer: '1.2.3', maxClientVer: '9.9.9'},
  trojan: {clients: [{password: 'synthetic-password', email: 'legacy-trojan'}]},
  shadowsocks: {method: 'aes-256-gcm', password: 'synthetic-password', clients: [{password: 'synthetic-user', email: 'legacy-ss'}]},
  hysteria: {version: 2, clients: [{auth: 'synthetic-password', email: 'legacy-hy'}]},
  mixed: {auth: 'password', accounts: [{user: 'synthetic', pass: 'synthetic'}], udp: true},
  http: {accounts: [{user: 'synthetic', pass: 'synthetic'}]},
  tunnel: {address: '127.0.0.1', port: 80, network: 'tcp'},
  tun: {name: 'test0', mtu: [1500, 1280], gateway: ['10.0.0.1/24']},
  wireguard: {secretKey: '', peers: [], mtu: 1420},
};
function context(source, native) {
  let n = 0;
  const sandbox = vm.createContext({console, TextEncoder, URL, btoa: value => Buffer.from(value, "binary").toString("base64"), location: {hostname: 'panel.example'},
    ObjectUtil: {isEmpty: v => v === null || v === undefined || v === '', isArrEmpty: v => !v || !v.length, clone: v => v === undefined ? undefined : JSON.parse(JSON.stringify(v)), cloneProps: (to, from) => Object.assign(to, from)},
    RandomUtil: {randomUUID: () => '11111111-2222-4333-8444-' + String(++n).padStart(12, '0'), randomLowerAndNum: () => `synthetic${++n}`, randomSeq: () => `synthetic${++n}`, randomInteger: () => 18080, randomShortIds: () => ['1234567890abcdef'], randomShadowsocksPassword: () => 'synthetic-password'},
    Wireguard: {generateKeypair: () => ({publicKey: 'synthetic-public-key', privateKey: 'synthetic-private-key'})},
    NumberFormatter: {toFixed: (n, precision) => Number(n.toFixed(precision))}, SizeFormatter: {ONE_GB: 1073741824},
  });
  vm.runInContext(source, sandbox);
  if (native) vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model/native-inbound.js'), 'utf8'), sandbox);
  return sandbox;
}
const source = process.env.INBOUND_BASELINE ? fs.readFileSync(process.env.INBOUND_BASELINE, 'utf8') : fs.readFileSync(path.join(root, 'web/assets/js/model/inbound.js'), 'utf8');
const ctx = context(source, !process.env.INBOUND_BASELINE);
function run(code, data) { ctx.data = data; return JSON.parse(vm.runInContext(`JSON.stringify((()=>{${code}})())`, ctx)); }
const legacy = {};
for (const [protocol, settings] of Object.entries(input)) legacy[protocol] = run('return Inbound.Settings.fromJson(data.protocol, data.settings).toJson();', {protocol, settings});
if (process.env.INBOUND_BASELINE) { process.stdout.write(JSON.stringify(legacy, null, 2) + '\n'); process.exit(0); }
const expected = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/legacy-inbound-roundtrips.json')));
assert.deepEqual(legacy, expected, 'all ten existing protocol serializers retain the baseline output');
let checks = 10;
const UUID = '11111111-2222-4333-8444-555555555555';
const PEM = '-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----';
const configs = {
  anytls: {clients: [{password: 'synthetic-password', email: 'anytls', level: 2, uuidHashMiddle: true}], handshakeTimeout: 10, maxStreams: 128},
  mieru: {clients: [{username: UUID, password: 'synthetic-password', email: 'mieru', uuidMetadataTrailer: true}], transport: 'udp', handshakeTimeout: 10},
  dnstt: {domain: 'tunnel.example', privateKey: '11'.repeat(32), inner: {protocol: 'vless'}, clients: [{id: UUID, email: 'dnstt'}], mtu: 1232},
  openvpn: {network: 'tcp', certificates: {ca: PEM, cert: PEM, key: '-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----'}, clients: [{commonName: 'synthetic-client', email: 'openvpn', clientProof: {keyId: 'test', key: '22'.repeat(32)}}], clientProof: {required: true}},
  shadowtls: {version: 3, strict: true, handshake: {address: 'tls.example', port: 443}, clients: [{password: UUID, email: 'shadowtls', innerUsername: 'synthetic', requireUuidSessionId: true}], inner: {protocol: 'socks', settings: {auth: 'password', accounts: [{user: 'synthetic', pass: 'synthetic'}], udp: false}}},
  orbit: {transport: 'tcp', tls: {certificate: PEM.split('\n'), key: ['-----BEGIN PRIVATE KEY-----', 'SYNTHETIC', '-----END PRIVATE KEY-----']}, clients: [{key: 'vck1_' + 'A'.repeat(86), email: 'orbit', expiresAt: 2000000000}]},
};
for (const [protocol, settings] of Object.entries(configs)) {
  settings.futureOption = {nested: ['keep', {flag: false}], exact: 0};
  settings.clients[0].futureClientOption = {nested: 'retained'};
  const result = run(`const settings = Inbound.Settings.fromJson(data.protocol, data.settings);
    const first = settings.toJson();
    settings.advancedJSON = JSON.stringify(first);
    const second = settings.toJson();
    const fresh = settings.newClient();
    return {first, second, errors: settings.validationErrors, id: Inbound.nativeClientId(data.protocol, settings.clients[0]), native: settings instanceof Inbound.NativeSettings, fresh: fresh.toJson()};`, {protocol, settings});
  assert.equal(result.native, true, protocol);
  assert.deepEqual(result.errors, [], protocol + ' valid fixture');
  assert.deepEqual(result.first, result.second, protocol + ' JSON/form round trip');
  for (const [key, value] of Object.entries(settings)) {
    if (key === 'clients') for (const [clientKey, clientValue] of Object.entries(value[0])) assert.deepEqual(result.second.clients[0][clientKey], clientValue, `${protocol} client ${clientKey}`);
    else assert.deepEqual(result.second[key], value, `${protocol} ${key}`);
  }
  assert.ok(result.id, protocol + ' identity');
  assert.ok(result.fresh.email && result.fresh.subId, protocol + ' new client keeps panel metadata');
  const malformed = run(`const s = new Inbound.NativeSettings(data.protocol, data.settings); const before = s.toJson(); s.advancedJSON = '{'; return {same: JSON.stringify(s.toJson()) === JSON.stringify(before), errors: s.validationErrors, text: s.advancedJSON};`, {protocol, settings});
  assert.equal(malformed.same, true, protocol + ' invalid JSON must not mutate saved fields');
  assert.equal(malformed.text, '{');
  assert.ok(malformed.errors.length);
  checks += 9;
}
const targeted = run(`
  const vmess = Inbound.VmessSettings.VMESS.fromJson({id:data.uuid,rawUuidAuth:true});
  const trojan = Inbound.TrojanSettings.Trojan.fromJson({password:data.uuid,uuidHashPrefix:true});
  const disabled = Inbound.VmessSettings.VMESS.fromJson({id:data.uuid,rawUuidAuth:false});
  const bad = Inbound.VmessSettings.VMESS.fromJson({id:data.uuid,rawUuidAuth:'invalid'});
  const s = new Inbound.NativeSettings('dnstt', data.dnstt);
  const privateField = s.fields.find(f => f.path === 'privateKey');
  s.setField(privateField, '33'.repeat(32));
  const changed = s.toJson();
  const client = new Inbound.NativeClient('mieru', {username:'not-a-uuid',password:'p',uuidMetadataTrailer:true});
  const duplicate = new Inbound.NativeSettings('anytls', {clients:[{password:'same',email:'a'},{password:'same',email:'b'}]});
  const proof = new Inbound.NativeSettings('openvpn', data.openvpn); delete proof.clients[0].data.clientProof;
  const wrongInner = new Inbound.NativeSettings('dnstt', data.dnstt); wrongInner.setField(wrongInner.fields.find(f => f.path === 'inner.protocol'),'socks');
  const a = new Inbound(); a.protocol = Protocols.ANYTLS;
  const m = new Inbound(); m.protocol = Protocols.MIERU;
  return {vmess:vmess.toJson(),trojan:trojan.toJson(),disabled:disabled.toJson(),bad:bad.toJson(),changed,wrongUuid:client.validationErrors,duplicate:duplicate.validationErrors,proof:proof.validationErrors,wrongInner:wrongInner.validationErrors,anytls:{network:a.network,security:a.stream.security,stream:a.canEnableStream(),tls:a.canEnableTls()},mieru:{stream:m.canEnableStream(),tls:m.canEnableTls()}};
`, {uuid: UUID, dnstt: configs.dnstt, openvpn: configs.openvpn});
assert.equal(targeted.vmess.rawUuidAuth, true);
assert.equal(targeted.trojan.uuidHashPrefix, true);
assert.equal(Object.hasOwn(targeted.disabled, 'rawUuidAuth'), false);
assert.equal(targeted.bad.rawUuidAuth, 'invalid', 'invalid auth types must not silently change authentication');
assert.equal(targeted.changed.privateKey, '33'.repeat(32));
assert.deepEqual(targeted.changed.futureOption, configs.dnstt.futureOption);
assert.ok(targeted.wrongUuid.length);
assert.ok(targeted.duplicate.length);
assert.ok(targeted.proof.length);
assert.ok(targeted.wrongInner.length);
assert.deepEqual(targeted.anytls, {network: 'tcp', security: 'tls', stream: true, tls: true});
assert.deepEqual(targeted.mieru, {stream: false, tls: false});
checks += 12;
for (const bad of [null, [], 'invalid', {clients: {}}, {clients: [null]}]) {
  assert.throws(() => run("return new Inbound.NativeSettings('anytls', data).toJson();", bad));
  checks++;
}
const extra = run(`
  const token = Inbound.nativeClientId('anytls', {email:'user/with?ü',password:'never-in-url'});
  const original = new Inbound.NativeSettings('openvpn',data.openvpn);
  original.clients[0].data.certificate='client-cert'; original.clients[0].data.privateKey='client-key';
  const copied = original.cloneForNewInbound();
  const shadow = new Inbound.NativeSettings('shadowtls',{version:2,password:'outer',handshake:{address:'tls.example'},clients:[{email:'one',innerUsername:'u'}],inner:{protocol:'socks',settings:{auth:'password',accounts:[{user:'u',pass:'p'}],udp:false}}});
  const ss=Inbound.ShadowsocksSettings.Shadowsocks.fromJson({method:'',password:data.uuid,uuidIdentityKeys:true});
  const bad=Inbound.VmessSettings.VMESS.fromJson({id:data.uuid,rawUuidAuth:null});
  const delays = [original.newClient(),original.newClient()]; delays[0].delayedStart=true; delays[0].delayedExpireDays=4;
  const orbit=new Inbound.NativeSettings('orbit',data.orbit); orbit.data.transport='quic';
  return {token,copy:copied.toJson(),original:original.toJson(),shadowErrors:shadow.validationErrors,shadowFields:shadow.clients[0].fields.map(f=>f.path),ss:ss.toJson(),ssStockErrors:Inbound.compatibilityErrors('shadowsocks',[ss],'aes-256-gcm'),ss2022Errors:Inbound.compatibilityErrors('shadowsocks',[ss],'2022-blake3-aes-128-gcm'),nullFlag:bad.toJson().rawUuidAuth,nullErrors:Inbound.compatibilityErrors('vmess',[bad]),delays:delays.map(c=>c.expiryTime),warning:orbit.help};
`, {openvpn:configs.openvpn,orbit:configs.orbit,uuid:UUID});
assert.equal(extra.token,'email:'+Buffer.from('user/with?ü').toString('base64url'));
assert.ok(!extra.token.includes('never-in-url'));
assert.notEqual(extra.copy.clients[0].email,extra.original.clients[0].email);
assert.notEqual(extra.copy.clients[0].subId,extra.original.clients[0].subId);
assert.deepEqual(extra.copy.certificates,extra.original.certificates);
assert.equal(extra.copy.clients[0].certificate,'client-cert');
assert.equal(extra.copy.clients[0].privateKey,'client-key');
assert.deepEqual(extra.shadowErrors,[]);
assert.ok(!extra.shadowFields.includes('password'));
assert.equal(extra.ss.uuidIdentityKeys,true);
assert.ok(extra.ssStockErrors.length);
assert.deepEqual(extra.ss2022Errors,[]);
assert.equal(extra.nullFlag,null);
assert.ok(extra.nullErrors.length);
assert.deepEqual(extra.delays,[-4*86400000,0]);
assert.match(extra.warning,/passive network observer/);
checks+=16;
const compatibility = run(`
  const settings=Inbound.ShadowsocksSettings.fromJson({method:'2022-blake3-aes-128-gcm',password:'server-key',uuidIdentityKeys:true,clients:[{email:'inherited',password:data.uuid},{email:'ordinary',password:'base64-user-key',uuidIdentityKeys:false}]});
  const initial=settings.toJson(); settings.shadowsockses[0].uuidIdentityKeys=false;
  const inner={protocol:'shadowsocks',settings:{network:'tcp',clients:[{email:'shadow',method:'chacha20-ietf-poly1305',password:'synthetic'}]}};
  const shadow=new Inbound.NativeSettings('shadowtls',{version:3,handshake:{address:'tls.example'},clients:[{email:'shadow',password:data.uuid}],inner});
  const copy=shadow.cloneForNewInbound();
  const socks=new Inbound.NativeSettings('dnstt',{domain:'t.example',privateKey:'11'.repeat(32),inner:{protocol:'socks'},clients:[{email:'user',username:'other',password:'p',totalGB:100}]});
  return {initial,edited:settings.toJson(),shadow:shadow.validationErrors,clone:copy.toJson(),quota:socks.validationErrors};
`,{uuid:UUID});
assert.equal(compatibility.initial.uuidIdentityKeys,true);
assert.equal(compatibility.initial.clients[0].uuidIdentityKeys,true);
assert.equal(compatibility.initial.clients[1].uuidIdentityKeys,false);
assert.equal(compatibility.edited.clients[0].uuidIdentityKeys,false);
assert.deepEqual(compatibility.shadow,[]);
assert.equal(compatibility.clone.clients[0].email,compatibility.clone.inner.settings.clients[0].email);
assert.ok(compatibility.quota.some(error=>error.includes('must match client email')));
checks+=7;
const switching=run(`const s=new Inbound.NativeSettings('dnstt',data);s.setField(s.fields.find(field=>field.path==='inner.protocol'),'socks');return {fields:s.clients[0].fields.map(field=>field.path),errors:s.validationErrors};`,configs.dnstt);
assert.ok(switching.fields.includes('username') && switching.fields.includes('password'));
assert.ok(!switching.fields.includes('id'));
assert.ok(switching.errors.length);
checks+=3;
const singleLabel=run(`
  const single=new Inbound.NativeSettings('dnstt',{domain:'tunnel',privateKey:'11'.repeat(32),inner:{protocol:'vless'},clients:[{id:data.uuid,email:'d'}]});
  const bad=new Inbound.NativeSettings('dnstt',{domain:'has a space',privateKey:'11'.repeat(32),inner:{protocol:'vless'},clients:[{id:data.uuid,email:'d'}]});
  const sockInner=new Inbound.NativeSettings('shadowtls',{version:2,handshake:{address:'tls.example'},clients:[{email:'one',innerUsername:'u'}],inner:{protocol:'socks',settings:{auth:'password',accounts:[{user:'u',pass:'p'}],udp:false}}});
  const ssInner=new Inbound.NativeSettings('shadowtls',{version:2,handshake:{address:'tls.example'},clients:[{email:'two',password:data.uuid}],inner:{protocol:'shadowsocks',settings:{network:'tcp',clients:[{email:'two',method:'chacha20-ietf-poly1305',password:'synthetic'}]}}});
  return {single:single.validationErrors,bad:bad.validationErrors,socksFields:sockInner.clients[0].fields.map(f=>f.path),ssFields:ssInner.clients[0].fields.map(f=>f.path)};
`,{uuid:UUID});
assert.ok(!singleLabel.single.some(error=>error.includes('DNS tunnel name')),'single-label tunnel domain is accepted like the core');
assert.ok(singleLabel.bad.some(error=>error.includes('DNS tunnel name')),'invalid tunnel domain is still rejected');
assert.ok(singleLabel.socksFields.includes('innerUsername'),'SOCKS inner keeps the inner username field');
assert.ok(!singleLabel.ssFields.includes('innerUsername'),'non-SOCKS inner hides the inner username field');
checks+=4;
const groups=run(`const inbounds=[{protocol:'vless',settings:'{"clients":[{"subId":"shared"}]}'},{protocol:'mieru',settings:'{"clients":[{"subId":"shared"}]}'}];return {shared:Inbound.subscriptionNeedsJSON(inbounds,'shared'),stock:Inbound.subscriptionNeedsJSON(inbounds,'stock'),bad:Inbound.subscriptionNeedsJSON([{protocol:'dnstt',settings:'{'}],'shared')};`);
assert.equal(groups.shared,true);
assert.equal(groups.stock,false);
assert.equal(groups.bad,false);
checks+=3;
console.log(`PASS ${checks} inbound native/legacy checks (no network)`);
