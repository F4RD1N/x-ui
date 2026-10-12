// Browser test of the xray-instance UI on the isolated panel.
// Usage: node xui_ui.js <panel-url> <user> <pass> <shots-dir>
const { chromium } = require('playwright');
const [, , PANEL, USER, PASS, SHOTS] = process.argv;
const results = [];
const check = (name, ok, detail) => {
  results.push(ok);
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (!ok && detail ? '  [' + detail + ']' : ''));
};

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || undefined });
  const errors = [];
  for (const [label, viewport, dark] of [['desktop', { width: 1366, height: 900 }, false], ['phone', { width: 390, height: 844 }, false], ['dark', { width: 1366, height: 900 }, true]]) {
    const ctx = await browser.newContext({ viewport, deviceScaleFactor: label === 'phone' ? 2 : 1 });
    if (dark) await ctx.addInitScript(() => localStorage.setItem('dark-mode', 'true'));
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errors.push(label + ': ' + e.message));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(label + ' console: ' + m.text()); });

    const login = await page.request.post(PANEL + '/login', { form: { username: USER, password: PASS } });
    check(label + ': login', login.ok());

    // Overview: the instances card fills in from the status feed.
    await page.goto(PANEL + '/panel/');
    await page.waitForSelector('.xi-card .xi-row', { timeout: 20000 });
    await page.waitForTimeout(4500); // two status ticks, so CPU use has a value
    const names = await page.$$eval('.xi-card .xi-name', (els) => els.map((e) => e.textContent.trim()));
    check(label + ': overview lists the instances', names.includes('xray-1') && names.includes('xray-2'), names.join(','));
    const cardText = await page.textContent('.xi-card');
    check(label + ': overview shows cores, CPU, TCP, memory', /CPU cores:\s*\d+/.test(cardText) && /TCP connections/.test(cardText) && /CPU\s*\d/.test(cardText), cardText.slice(0, 200));
    const card = await page.$('.xi-card');
    await card.scrollIntoViewIfNeeded();
    await card.screenshot({ path: `${SHOTS}/${label}-overview-instances.png` });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(label + ': overview has no horizontal scroll', overflow <= 0, overflow + 'px');

    // Inbounds list: each inbound shows its instance.
    await page.goto(PANEL + '/panel/inbounds');
    await page.waitForSelector('.ant-table-row', { timeout: 20000 });
    if (label === 'desktop') {
      const tags = await page.$$eval('.ant-table-row .ant-tag-orange', (els) => els.map((e) => e.textContent.trim()));
      check('desktop: inbound list shows instance tags', tags.some((t) => /^xray-\d+$/.test(t)), tags.join(','));
    }

    // Add inbound: instance and cores fields.
    await page.click('button.ant-btn-primary:has(.anticon-plus)');
    await page.waitForSelector('#inbound-modal .ant-modal-body', { timeout: 10000 });
    await page.waitForTimeout(800);
    const modal = await page.$('#inbound-modal .ant-modal-body');
    const modalText = await modal.textContent();
    check(label + ': form has Xray instance and CPU cores', modalText.includes('Xray instance') && modalText.includes('CPU cores'));
    const inst = await page.inputValue('#inbound-modal .ant-select-auto-complete input');
    check(label + ': new inbound gets the next instance name', /^xray-\d+$/.test(inst), inst);
    const hint = await page.textContent('#inbound-modal .xray-instance-hint');
    const m = hint.match(/Total cores:\s*(\d+).*Available:\s*(\d+)/s);
    check(label + ': form shows total and available cores', m && +m[1] > 0, hint);
    // Fixed cores: the number box appears and is capped at what is available.
    await page.click('#inbound-modal .ant-radio-button-wrapper:has-text("Fixed")');
    await page.waitForSelector('#inbound-modal .ant-input-number', { timeout: 5000 });
    await page.waitForTimeout(600); // let the button transition finish before the screenshot
    const max = await page.$eval('#inbound-modal .ant-form-item:has-text("CPU cores") .ant-input-number-input', (e) => e.getAttribute('aria-valuemax'));
    check(label + ': fixed cores are capped at the available cores', m && max === m[2], `max=${max} available=${m && m[2]}`);
    await modal.screenshot({ path: `${SHOTS}/${label}-inbound-form.png` });
    // Typing an existing instance takes over its cores.
    await page.fill('#inbound-modal .ant-select-auto-complete input', 'xray-1');
    await page.waitForTimeout(300);
    const mode = await page.$eval('#inbound-modal .ant-radio-button-wrapper-checked', (e) => e.textContent.trim());
    check(label + ': picking an existing instance takes its cores', mode === 'Auto', mode);
    const shared = await page.textContent('#inbound-modal .ant-form-item:has-text("Xray instance")');
    check(label + ': form lists the other inbounds of that instance', /Also runs:/.test(shared), shared.slice(0, 120));
    const formOverflow = await page.evaluate(() => {
      const b = document.querySelector('#inbound-modal .ant-modal-body');
      return b.scrollWidth - b.clientWidth;
    });
    check(label + ': form has no horizontal scroll', formOverflow <= 0, formOverflow + 'px');
    await ctx.close();
  }
  check('no JS errors', errors.length === 0, errors.slice(0, 5).join(' | '));
  await browser.close();
  const failed = results.filter((r) => !r).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
})();
