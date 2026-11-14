'use strict';

// Freedom's "udpRouteEachDestination" in the panel's outbound model: kept on
// import/edit/export, written only when on, so templates that do not use it
// stay byte-identical. Run: node --test tests/dialect11/outbound-freedom.test.js
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const context = vm.createContext({console, URL, URLSearchParams, TextEncoder, TextDecoder});
vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/util/index.js'), 'utf8'), context);
vm.runInContext(fs.readFileSync(path.join(root, 'web/assets/js/model/outbound.js'), 'utf8') + '\nglobalThis.models = {Outbound, Protocols};', context);
const {Outbound} = context.models;
const clean = value => JSON.parse(JSON.stringify(value));
const roundTrip = json => clean(Outbound.fromJson(json).toJson());

test('a freedom outbound with udpRouteEachDestination on keeps it', () => {
    // in the order the model writes its keys, so the text can be compared too
    const input = {protocol: 'freedom', settings: {domainStrategy: 'AsIs', udpRouteEachDestination: true}, tag: 'direct'};
    const output = roundTrip(input);
    assert.deepEqual(output, input);
    assert.equal(JSON.stringify(output), JSON.stringify(input));
});

test('off or absent is not written, so existing templates do not change', () => {
    for (const settings of [{}, {domainStrategy: 'AsIs'}, {domainStrategy: 'AsIs', udpRouteEachDestination: false}]) {
        const output = roundTrip({tag: 'direct', protocol: 'freedom', settings});
        assert.equal('udpRouteEachDestination' in output.settings, false, JSON.stringify(settings));
    }
    const plain = {protocol: 'freedom', settings: {domainStrategy: 'AsIs'}, tag: 'direct'};
    assert.equal(JSON.stringify(roundTrip(plain)), JSON.stringify(plain));
});

test('only a real true turns it on', () => {
    for (const value of ['true', 1, 'yes', null, {}]) {
        const model = Outbound.fromJson({tag: 'direct', protocol: 'freedom', settings: {udpRouteEachDestination: value}});
        assert.equal(model.settings.udpRouteEachDestination, false, JSON.stringify(value));
    }
});

test('a new freedom outbound starts with it off and can be switched on and off', () => {
    const model = new Outbound('direct', 'freedom');
    assert.equal(model.settings.udpRouteEachDestination, false);
    assert.equal('udpRouteEachDestination' in clean(model.toJson()).settings, false);
    model.settings.udpRouteEachDestination = true;
    assert.equal(clean(model.toJson()).settings.udpRouteEachDestination, true);
    model.settings.udpRouteEachDestination = false;
    assert.equal('udpRouteEachDestination' in clean(model.toJson()).settings, false);
});

test('it sits next to the other freedom settings without disturbing them', () => {
    const input = {tag: 'direct', protocol: 'freedom', settings: {
        domainStrategy: 'UseIPv4', redirect: '1.1.1.1:53', ipsBlocked: ['geoip:private'],
        fragment: {packets: 'tlshello', length: '100-200', interval: '10-20', maxSplit: '4'},
        noises: [{type: 'rand', packet: '10-20', delay: '10-16', applyTo: 'ip'}],
        udpRouteEachDestination: true}};
    assert.deepEqual(roundTrip(input), input);
});
