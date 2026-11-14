'use strict';

// Freedom's "Route each UDP" switch (udpRouteEachDestination), rendered from the real form
// and modal templates in headless Chromium: open a freedom outbound, toggle
// the switch, save, and check the outbound JSON the page would store.
// PLAYWRIGHT_MODULE and CHROME may point to an existing installation; no
// panel, login or network is used.
//   PLAYWRIGHT_MODULE=/root/ads-browser/driver/node_modules/playwright-core \
//   CHROME=/usr/bin/google-chrome node tests/dialect11/outbound-freedom-udp-route-ui.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-udproute-ui-'));
const file = relative => pathToFileURL(path.join(root, relative)).href;
const clean = html => html.replace(/{{\s*(?:define|end)[^}]*}}/g, '').replace(/{{\s*i18n\s+"([^"]+)"\s*}}/g, '$1');
const form = clean(fs.readFileSync(path.join(root, 'web/html/form/outbound.html'), 'utf8'));
const modal = clean(fs.readFileSync(path.join(root, 'web/html/modals/xray_outbound_modal.html'), 'utf8').replace('{{template "form/outbound"}}', form));
fs.writeFileSync(path.join(temp, 'f.html'), `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="${file('web/assets/ant-design-vue/antd.min.css')}"></head><body>
<script src="${file('web/assets/vue/vue.min.js')}"></script>
<script src="${file('web/assets/moment/moment.min.js')}"></script>
<script src="${file('web/assets/ant-design-vue/antd.min.js')}"></script>
<script src="${file('web/assets/codemirror/codemirror.min.js')}"></script>
<script src="${file('web/assets/js/util/index.js')}"></script>
<script src="${file('web/assets/js/model/outbound.js')}"></script>
<script>window.themeSwitcher={currentTheme:'light'}; window.app={cmOptions:{}}; Vue.config.productionTip=false;</script>
${modal}</body></html>`);

// The owner's allow-list "direct" outbound, as it is in the template.
const direct = {tag: 'direct', protocol: 'freedom', settings: {domainStrategy: 'AsIs', redirect: '', noises: []}};
// What the form saves for it unchanged (it never writes empty settings).
const directSaved = {tag: 'direct', protocol: 'freedom', settings: {domainStrategy: 'AsIs'}};

(async () => {
    const errors = [];
    const browser = await chromium.launch({headless: true, executablePath: process.env.CHROME || undefined, args: ['--no-sandbox']});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        await page.route(/^https?:\/\//, r => r.abort());
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(pathToFileURL(path.join(temp, 'f.html')).href);
        await page.waitForFunction(() => typeof outModal !== 'undefined');
        const show = ob => page.evaluate(ob => {
            window.saved = null;
            outModal.show({isEdit: true, outbound: ob, confirm: o => { window.saved = JSON.parse(JSON.stringify(o)); }, tags: []});
        }, ob);
        const item = page.locator('#out-modal .ant-form-item').filter({hasText: 'Route each UDP'});
        const sw = item.locator('.ant-switch');
        const isOn = async () => /\bant-switch-checked\b/.test(await sw.getAttribute('class'));

        // an outbound without the setting: the switch is there and off
        await show(direct);
        await page.waitForTimeout(300);
        assert.equal(await item.count(), 1, 'one "Route each UDP" row in the freedom form');
        const label = item.locator('.ant-form-item-label');
        // not cut off: it fits as well as the form's widest other label does
        const chain = page.locator('#out-modal .ant-form-item-label').filter({hasText: 'Chain through outbound'});
        const over = el => el.scrollWidth - el.clientWidth;
        assert.ok(await label.evaluate(over) <= Math.max(0, await chain.evaluate(over)), 'the label is cut off');
        assert.equal(await isOn(), false);

        // its help text is in the label's tooltip, like the form's other help
        await item.locator('.anticon-question-circle').hover();
        await page.waitForTimeout(400);
        assert.match(await page.locator('.ant-tooltip:visible').innerText(), /^Route each UDP destination, not only a session's first one:[\s\S]*dropped/);

        // switch it on and save: the key is in the outbound, the rest as it was
        await sw.click();
        await page.waitForTimeout(200);
        assert.equal(await isOn(), true);
        await page.screenshot({path: path.join(temp, 'switch-on.png')});
        await page.evaluate(() => outModal.ok());
        let saved = await page.evaluate(() => window.saved);
        assert.deepEqual(saved, {...directSaved, settings: {...directSaved.settings, udpRouteEachDestination: true}});

        // the complete-JSON editor shows it too
        await page.evaluate(() => outModal.toggleJson(true));
        await page.waitForTimeout(200);
        assert.equal(JSON.parse(await page.locator('#outboundJson').inputValue()).settings.udpRouteEachDestination, true);
        await page.evaluate(() => outModal.toggleJson(false));

        // reopened from what was saved, it is on; switched off, the key goes
        await show(saved);
        await page.waitForTimeout(300);
        assert.equal(await isOn(), true);
        await sw.click();
        await page.waitForTimeout(200);
        await page.evaluate(() => outModal.ok());
        saved = await page.evaluate(() => window.saved);
        assert.deepEqual(saved, directSaved);
        assert.equal('udpRouteEachDestination' in saved.settings, false);

        // only freedom has it
        await show({tag: 'blocked', protocol: 'blackhole', settings: {}});
        await page.waitForTimeout(300);
        assert.equal(await item.count(), 0, 'not shown for other protocols');

        assert.deepEqual(errors, []);
        console.log('ok: freedom "Route each UDP" switch (' + temp + ')');
    } finally {
        await browser.close();
    }
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
