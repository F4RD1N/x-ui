'use strict';

// The outbound form's "IP pool" dropdown, rendered from the real form and modal
// templates in headless Chromium. PLAYWRIGHT_MODULE and CHROME may point to an
// existing installation; no panel, login or network is used.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-ippool-ui-'));
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
const ranges = [
    {cidr: '103.76.130.0/24', label: '103.76.130.12, .79 – .80', ips: ['103.76.130.12', '103.76.130.79', '103.76.130.80']},
    {cidr: '154.193.163.96/27', label: '154.193.163.98 – .126', ips: Array.from({length: 29}, (_, i) => `154.193.163.${98 + i}`)},
];
(async () => {
    const errors = [];
    const browser = await chromium.launch({headless: true, executablePath: process.env.CHROME || undefined, args: ['--no-sandbox']});
    try {
        const page = await browser.newPage({viewport: {width: 1366, height: 900}});
        await page.route(/^https?:\/\//, r => r.abort());
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(pathToFileURL(path.join(temp, 'f.html')).href);
        await page.waitForFunction(() => typeof outModal !== 'undefined');

        // edit an outbound that has no pool yet: "none", Send Through editable
        await page.evaluate(r => {
            window.saved = null;
            outModal.show({isEdit: true, outbound: {tag: 'direct', protocol: 'freedom', sendThrough: '103.76.130.79', settings: {}},
                confirm: (ob, pool) => { window.saved = {ob, pool}; }, tags: [], ipRanges: r});
        }, ranges);
        await page.waitForTimeout(300);
        const sendThrough = page.locator('#out-modal input[placeholder^="IP, or IP1"]');
        assert.equal(await sendThrough.isDisabled(), false, 'Send Through is editable with no pool');
        const select = page.locator('#out-modal .ant-form-item').filter({hasText: 'IP pool'}).locator('.ant-select');
        assert.match(await select.innerText(), /none/);

        // the dropdown lists "none" and every range with its count
        await select.click();
        await page.waitForTimeout(300);
        const options = await page.locator('.ant-select-dropdown:visible li[role="option"]').allInnerTexts();
        assert.deepEqual(options.map(s => s.trim()), ['none', '103.76.130.12, .79 – .80 (3 IPs)', '154.193.163.98 – .126 (29 IPs)']);
        await page.locator('.ant-select-dropdown:visible li[role="option"]', {hasText: '154.193.163.98 – .126'}).click();
        await page.waitForTimeout(300);
        assert.equal(await sendThrough.isDisabled(), true, 'Send Through is locked while a pool is chosen');
        const note = await page.locator('#out-modal').innerText();
        assert.match(note, /Send Through is not used: Xray sends through these 29 IPs\./);
        assert.match(await select.innerText(), /154\.193\.163\.98 – \.126 \(29 IPs\)/);
        await page.screenshot({path: path.join(temp, 'pool-chosen.png')});

        // OK hands the pool to the page together with the unchanged outbound
        await page.evaluate(() => outModal.ok());
        const saved = await page.evaluate(() => window.saved);
        assert.equal(saved.pool, '154.193.163.96/27');
        assert.equal(saved.ob.tag, 'direct');
        assert.equal(saved.ob.sendThrough, '103.76.130.79', 'the typed Send Through stays in the template');

        // a stored pool that is no longer on the server is shown as such
        await page.evaluate(r => outModal.show({isEdit: true, outbound: {tag: 'direct', protocol: 'freedom', settings: {}}, confirm: () => {}, tags: [], ipRanges: r, ipPool: '45.198.36.96/27'}), ranges);
        await page.waitForTimeout(300);
        assert.match(await page.locator('#out-modal').innerText(), /no longer on this server[\s\S]*Not on this server: Send Through above is used\./);

        // a new outbound starts at "none"
        await page.evaluate(r => outModal.show({confirm: () => {}, tags: [], ipRanges: r}), ranges);
        await page.waitForTimeout(300);
        assert.equal(await page.evaluate(() => outModal.ipPool), 'none');
        assert.deepEqual(errors, []);
        console.log('ok: IP pool dropdown (' + temp + ')');
    } finally {
        await browser.close();
    }
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
