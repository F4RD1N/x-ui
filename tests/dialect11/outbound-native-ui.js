'use strict';

// Runs only local UI fixtures. PLAYWRIGHT_MODULE and CHROME may point to an
// existing installation; no browser download, panel login or external traffic.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-outbound-ui-'));
const file = relative => pathToFileURL(path.join(root, relative)).href;
const cleanTemplate = html => html.replace(/{{\s*(?:define|end)[^}]*}}/g, '').replace(/{{\s*i18n\s+"([^"]+)"\s*}}/g, '$1');
const form = cleanTemplate(fs.readFileSync(path.join(root, 'web/html/form/outbound.html'), 'utf8'));
const modal = cleanTemplate(fs.readFileSync(process.env.OUTBOUND_MODAL_TEMPLATE || path.join(root, 'web/html/modals/xray_outbound_modal.html'), 'utf8').replace('{{template "form/outbound"}}', form));
const pageHTML = `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="${file('web/assets/ant-design-vue/antd.min.css')}"><link rel="stylesheet" href="${file('web/assets/codemirror/codemirror.min.css')}"></head><body>
<script src="${file('web/assets/vue/vue.min.js')}"></script>
<script src="${file('web/assets/moment/moment.min.js')}"></script>
<script src="${file('web/assets/ant-design-vue/antd.min.js')}"></script>
<script src="${file('web/assets/codemirror/codemirror.min.js')}"></script>
<script src="${file('web/assets/js/util/index.js')}"></script>
<script src="${file('web/assets/js/model/outbound.js')}"></script>
<script>window.themeSwitcher={currentTheme:'light'}; window.app={cmOptions:{lineNumbers:true}}; Vue.config.productionTip=false;</script>
${modal}</body></html>`;
const fixtureFile = path.join(temp, 'fixture.html');
fs.writeFileSync(fixtureFile, pageHTML);
const uuid = '40ab8f72-44ee-4e7d-984c-c5633ec89fe1';
const fixtures = {
    orbit: {address: '127.0.0.1', port: 1443, key: 'fixture-key', transport: 'tcp'},
    dnstt: {domain: 'tunnel.example.test', publicKey: '12'.repeat(32), resolvers: [{transport: 'udp', address: '127.0.0.1:5353'}], inner: {protocol: 'vless', uuid}},
    openvpn: {server: {address: '127.0.0.1', port: 1194, network: 'tcp'}, certificates: {ca: 'CA\nPEM', cert: 'CERT\nPEM', key: 'KEY\nPEM'}, advanced: {dev: 'tun', nobind: true, remoteCertTls: 'server', mtu: 1400}},
    anytls: {address: '127.0.0.1', port: 1443, password: 'fixture-password', tlsSettings: {serverName: 'localhost'}},
    shadowtls: {address: '127.0.0.1', port: 1443, password: uuid, version: 3, serverName: 'localhost'},
    mieru: {address: '127.0.0.1', port: 1443, username: uuid, password: 'fixture-password', transport: 'udp'},
};
(async () => {
    let browser;
    const errors = [];
    const checks = [];
    try {
        browser = await chromium.launch({headless: true, executablePath: process.env.CHROME || undefined, args: ['--no-sandbox', '--disable-dev-shm-usage']});
        const page = await browser.newPage();
        page.on('pageerror', error => errors.push(error.message));
        page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
        await page.goto(pathToFileURL(fixtureFile).href);
        await page.waitForFunction(() => typeof Outbound !== 'undefined' && typeof outModal !== 'undefined');
        for (const [layout, width, height, theme] of [['desktop', 1366, 900, 'light'], ['mobile', 390, 844, 'dark']]) {
            await page.setViewportSize({width, height});
            for (const [protocol, settings] of Object.entries(fixtures)) {
                const input = {tag: 'fixture-' + protocol, protocol, settings: {...settings, futureField: {retained: true}}};
                await page.evaluate(({input, theme}) => { themeSwitcher.currentTheme = theme; outModal.show({outbound: input, isEdit: true}); }, {input, theme});
                await page.waitForSelector('.ant-modal-body .ant-form');
                await page.waitForFunction(() => outModal.isValid);
                const label = protocol === 'dnstt' ? 'Delegated tunnel domain' : 'Server address';
                const item = page.locator('.ant-modal-body .ant-form-item').filter({has: page.locator('.ant-form-item-label', {hasText: label})}).first();
                const value = protocol === 'dnstt' ? 'edited.example.test' : '127.0.0.2';
                await item.locator('input').first().fill(value);
                await item.locator('input').first().press('Tab');
                const exported = await page.evaluate(() => outModal.outbound.toJson());
                const valueRead = protocol === 'dnstt' ? exported.settings.domain : protocol === 'openvpn' ? exported.settings.server.address : exported.settings.address;
                assert.equal(valueRead, value, protocol + ' typed control must update settings');
                assert.deepEqual(exported.settings.futureField, {retained: true});
                await page.evaluate(() => outModal.toggleJson(true));
                await page.waitForSelector('.CodeMirror');
                await page.evaluate(() => { outModal.cm.setValue(JSON.stringify(outModal.outbound.toJson(), null, 2)); outModal.toggleJson(false); });
                assert.equal(await page.evaluate(() => outModal.isValid), true);
                assert.deepEqual((await page.evaluate(() => outModal.outbound.toJson())).settings, exported.settings);
                // Use the actual Ant modal event, which does not preserve the
                // receiver of an unbound nested-object method reference.
                await page.evaluate(() => { window.submitted = []; outModal.confirm = value => window.submitted.push(value); });
                await page.locator('.ant-modal-footer button.ant-btn-primary').click();
                const submitted = await page.evaluate(() => window.submitted);
                assert.equal(submitted.length, 1, protocol + ' actual modal OK submits exactly once; browser errors: ' + errors.join('; '));
                assert.deepEqual(submitted[0], exported, protocol + ' actual modal OK retains exported settings');
                checks.push({layout, protocol, typedEdit: true, jsonRoundTrip: true, actualOKClick: true});
            }
        }
        // Exercise conditional controls which are hidden by ordinary fixtures.
        await page.evaluate(() => outModal.show({isEdit: true, outbound: {tag: 'orbit-wss', protocol: 'orbit', settings: {address: '127.0.0.1', port: 443, key: 'fixture-key', transport: 'wss', host: 'localhost', browser: true}}}));
        await page.waitForFunction(() => outModal.isValid);
        await page.waitForSelector('.ant-modal-body .ant-select');
        assert.equal(await page.evaluate(() => outModal.outbound.settings.value(outModal.outbound.settings.fields.find(field => field.path === 'browser'))), 'on');
        assert.equal(await page.evaluate(() => outModal.outbound.toJson().settings.browser), true);
        await page.evaluate(() => outModal.show({isEdit: true, outbound: {tag: 'inner-socks', protocol: 'socks', settings: {servers: [{address: '127.0.0.1', port: 1080, users: []}]}}}));
        const chainSwitch = page.locator('.ant-modal-body .ant-form-item').filter({has: page.locator('.ant-form-item-label', {hasText: 'Chain through outbound'})}).locator('button[role="switch"]');
        await chainSwitch.click();
        const chainInput = page.locator('.ant-modal-body .ant-form-item').filter({has: page.locator('.ant-form-item-label', {hasText: 'Carrier outbound tag'})}).locator('input');
        await chainInput.fill('shadowtls-carrier'); await chainInput.press('Tab');
        assert.deepEqual(await page.evaluate(() => outModal.outbound.toJson().proxySettings), {tag: 'shadowtls-carrier', transportLayer: true});
        assert.equal(await page.evaluate(() => outModal.isValid), true);
        await page.evaluate(() => { window.submitted = []; outModal.confirm = value => window.submitted.push(value); });
        await page.locator('.ant-modal-footer button.ant-btn-primary').click();
        assert.equal(await page.evaluate(() => window.submitted.length), 1, 'legacy SOCKS actual modal OK submits exactly once');
        assert.deepEqual(await page.evaluate(() => window.submitted[0].proxySettings), {tag: 'shadowtls-carrier', transportLayer: true});
        checks.push({orbitBrowserAlias: 'retained', shadowtlsInnerChaining: 'edited', legacyActualOKClick: true});
        await page.evaluate(uuid => {outModal.show({outbound:{tag:'ss2022',protocol:'shadowsocks',settings:{servers:[{address:'127.0.0.1',port:443,method:'2022-blake3-aes-128-gcm',password:'MTIzNDU2Nzg5MDEyMzQ1Ng==:'+uuid}]}},isEdit:true});},uuid);
        const identityControl=page.locator('.ant-modal-body .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'UUID identity key import compatibility'})}).first();
        await identityControl.locator('button[role="switch"]').click();
        assert.equal(await page.evaluate(()=>outModal.outbound.toJson().settings.servers[0].uuidIdentityKeys),true);
        assert.equal(await page.evaluate(()=>outModal.isValid),true);
        await page.evaluate(()=>{outModal.outbound.settings.method='aes-256-gcm';outModal.check();});
        assert.equal(await page.evaluate(()=>outModal.isValid),false);
        await identityControl.locator('button[role="switch"]').click();
        assert.equal(await page.evaluate(()=>outModal.isValid),true);
        checks.push({ss2022IdentityToggle:true,unsupportedMethodRejected:true});
        await page.evaluate(()=>{outModal.show({outbound:{tag:'quic',protocol:'orbit',settings:{link:'orbit://192.0.2.1:8443@vck1_'+'A'.repeat(86)+'&transport=quic'}},isEdit:true});});
        assert.equal(await page.evaluate(()=>outModal.outbound.toJson().settings.link.includes('transport=quic')),true);
        assert.equal(await page.locator('.ant-modal-body .ant-alert-info, .ant-modal-body .ant-alert-warning').count(),0);
        checks.push({orbitQuicSettingsRetained:true,conciseForm:true});
        await page.evaluate(() => { outModal.toggleJson(true); outModal.cm.setValue('{broken'); outModal.check(); });
        assert.equal(await page.evaluate(() => outModal.isValid), false);
        assert.equal(await page.locator('.ant-modal-footer button.ant-btn-primary').isDisabled(), true, 'invalid JSON disables actual modal OK');
        await page.evaluate(() => { window.submitted = 0; outModal.confirm = () => window.submitted++; outModal.ok(); });
        assert.equal(await page.evaluate(() => window.submitted), 0);
        for (const bad of ['null', '[]', '"invalid"']) {
            await page.evaluate(bad => { outModal.cm.setValue(bad); outModal.check(); }, bad);
            assert.equal(await page.evaluate(() => outModal.isValid), false);
        }
        checks.push({malformedJSON: 'rejected', staleSubmission: 'prevented'});
        assert.deepEqual(errors, []);
        console.log(JSON.stringify({passed: true, checks, pageErrors: errors}, null, 2));
    } finally {
        if (browser) await browser.close();
        fs.rmSync(temp, {recursive: true, force: true});
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
