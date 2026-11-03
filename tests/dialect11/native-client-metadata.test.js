'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const sandbox = vm.createContext({console, TextEncoder, URL,
    ObjectUtil: {isEmpty: value => value == null || value === '', isArrEmpty: value => !value?.length, cloneProps: (to, from) => Object.assign(to, from)},
    RandomUtil: {randomUUID: () => '11111111-2222-4333-8444-555555555555', randomLowerAndNum: () => 'fixture-id'},
});
for (const file of ['inbound.js', 'native-inbound.js']) vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model', file), 'utf8'), sandbox);
const NativeClient = vm.runInContext('Inbound.NativeClient', sandbox);
const credentials = {
    orbit: {key: 'vck1_' + 'A'.repeat(86)}, dnstt: {id: '11111111-2222-4333-8444-555555555555'},
    openvpn: {commonName: 'fixture-client'}, anytls: {password: 'fixture-password'},
    shadowtls: {password: 'fixture-password'}, mieru: {username: 'fixture-user', password: 'fixture-password'},
};
for (const [protocol, auth] of Object.entries(credentials)) {
    test(protocol + ' normalizes optional Telegram metadata without changing account fields', () => {
        for (const [input, expected] of [[undefined,0],[null,0],['',0],['  ',0],[0,0],[123,123],[-123,-123],['123',123],[' -123 ',-123],[Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER],[Number.MIN_SAFE_INTEGER,Number.MIN_SAFE_INTEGER]]) {
            const client = new NativeClient(protocol, {...auth, email: 'client', subId: 'saved-subscription', comment: 'keep', limitIp: 2, tgId: input});
            const output = client.toJson();
            assert.equal(output.tgId, expected);
            assert.equal(typeof output.tgId, 'number');
            assert.equal(output.subId, 'saved-subscription');
            assert.equal(output.comment, 'keep');
            assert.equal(output.limitIp, 2);
            assert.ok(!client.validationErrors.some(error => error.includes('Telegram ID')));
        }
    });
    test(protocol + ' invalid Telegram input blocks saving and stays renderable/backend-rejectable', () => {
        for (const input of ['not-a-number','1e3','0x20','1.5','9007199254740992',1.5,NaN,Infinity,-Infinity,Number.MAX_SAFE_INTEGER+1,true,false,{},[]]) {
            const client = new NativeClient(protocol, {...auth, email: 'client'});
            client.tgId = input;
            assert.ok(client.validationErrors.some(error => error.includes('Telegram ID')));
            const output = JSON.parse(JSON.stringify(client.toJson()));
            assert.equal(typeof output.tgId, 'string');
            assert.notEqual(output.tgId, 0);
            assert.equal(client.tgId, input, 'raw user input is not overwritten');
        }
    });
}
