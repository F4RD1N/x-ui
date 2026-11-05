'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.resolve(__dirname, '../../web/html/xray.html'), 'utf8');
const begin = html.indexOf('      async loadCustomGeoAliases() {');
const end = html.indexOf('\n    },\n    async mounted()', begin);
assert.ok(begin >= 0 && end > begin, 'Actual Xray page alias-loading method must be present.');
const clean = value => JSON.parse(JSON.stringify(value));

function fixture(response, suffix = '') {
    const requests = [], warnings = [], errors = [];
    const context = vm.createContext({
        HttpUtil: {async get(url) {
            requests.push(url);
            if (response instanceof Error) throw response;
            return response;
        }},
        console: {
            warn: (...args) => warnings.push(args),
            error: (...args) => errors.push(args),
        },
    });
    const methods = vm.runInContext('({' + html.slice(begin, end) + '})', context);
    methods.customGeoAliasLabelSuffix = suffix;
    methods.settingsData = {
        IPsOptions: [{label: 'existing IP', value: 'geoip:private'}],
        DomainsOptions: [{label: 'existing domain', value: 'geosite:private'}],
        BlockDomainsOptions: [{label: 'existing block', value: 'geosite:category-ads-all'}],
    };
    return {methods, requests, warnings, errors};
}

for (const [name, obj] of [
    ['null object', null],
    ['absent arrays', {}],
    ['null arrays from an empty database', {geoip: null, geosite: null}],
    ['empty arrays', {geoip: [], geosite: []}],
    ['non-array values', {geoip: {}, geosite: 'invalid'}],
]) {
    test('Xray geo aliases: ' + name + ' leave default options intact without console errors', async () => {
        const f = fixture({success: true, obj});
        const before = clean(f.methods.settingsData);
        await f.methods.loadCustomGeoAliases();
        assert.deepEqual(clean(f.methods.settingsData), before);
        assert.deepEqual(f.requests, ['/panel/api/custom-geo/aliases']);
        assert.deepEqual(f.warnings, []);
        assert.deepEqual(f.errors, []);
    });
}

test('Xray geo aliases: actual arrays populate their corresponding selectors', async () => {
    const response = {success: true, obj: {
        geoip: [{alias: 'private-network', extExample: 'ext:custom-ip.dat:private-network'}],
        geosite: [{alias: 'private-sites', extExample: 'ext:custom-site.dat:private-sites'}],
    }};
    const before = clean(response);
    const f = fixture(response, ' (custom)');
    await f.methods.loadCustomGeoAliases();
    assert.deepEqual(clean(f.methods.settingsData.IPsOptions.slice(1)), [
        {label: 'private-network (custom)', value: 'ext:custom-ip.dat:private-network'},
    ]);
    const domains = [{label: 'private-sites (custom)', value: 'ext:custom-site.dat:private-sites'}];
    assert.deepEqual(clean(f.methods.settingsData.DomainsOptions.slice(1)), domains);
    assert.deepEqual(clean(f.methods.settingsData.BlockDomainsOptions.slice(1)), domains);
    assert.deepEqual(response, before, 'Loading aliases must not mutate the API response.');
    assert.deepEqual(f.errors, []);
});

test('Xray geo aliases: a missing list does not suppress the other valid list', async () => {
    const f = fixture({success: true, obj: {
        geoip: null,
        geosite: [{alias: 'sites', extExample: 'ext:sites.dat:sites'}],
    }});
    await f.methods.loadCustomGeoAliases();
    assert.equal(f.methods.settingsData.IPsOptions.length, 1);
    assert.deepEqual(clean(f.methods.settingsData.DomainsOptions[1]), {label: 'sites', value: 'ext:sites.dat:sites'});
    assert.equal(f.methods.settingsData.BlockDomainsOptions.length, 2);
    assert.deepEqual(f.errors, []);
});

test('Xray geo aliases: rejected API response leaves options intact and reports a warning', async () => {
    const f = fixture({success: false, msg: 'temporarily unavailable'});
    const before = clean(f.methods.settingsData);
    await f.methods.loadCustomGeoAliases();
    assert.deepEqual(clean(f.methods.settingsData), before);
    assert.deepEqual(f.warnings, [['Failed to load custom geo aliases:', 'temporarily unavailable']]);
    assert.deepEqual(f.errors, []);
});

test('Xray geo aliases: transport failure is handled without rejecting page initialization', async () => {
    const failure = new Error('offline');
    const f = fixture(failure);
    const before = clean(f.methods.settingsData);
    await assert.doesNotReject(f.methods.loadCustomGeoAliases());
    assert.deepEqual(clean(f.methods.settingsData), before);
    assert.equal(f.errors.length, 1);
    assert.equal(f.errors[0][0], 'Failed to load custom geo aliases:');
    assert.equal(f.errors[0][1], failure);
});
