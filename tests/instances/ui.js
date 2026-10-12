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

    // Overview: one card per instance, filled from the status feed.
    await page.goto(PANEL + '/panel/');
    await page.waitForSelector('.xi-card', { timeout: 20000 });
    await page.waitForTimeout(4500); // two status ticks, so CPU use has a value
    const names = await page.$$eval('.xi-card .xi-name', (els) => els.map((e) => e.textContent.trim()));
    check(label + ': overview has a card per instance', names.includes('xray-1') && names.includes('xray-2') && names.length === new Set(names).size, names.join(','));
    const summary = await page.textContent('.xi-summary');
    check(label + ': summary card shows CPU cores, fixed, for auto', /Xray instances/.test(summary) && /CPU cores\s*\d+/.test(summary) && /Fixed\s*\d+/.test(summary) && /For auto\s*\d+/.test(summary), summary);
    const cores = await page.$$eval('.xi-card .xi-coresline', (els) => els.map((e) => e.textContent.trim()));
    check(label + ': cores read like "Auto · 4 Core (0-3)"', cores.length > 0 && cores.every((t) => /^(Auto|Fixed) · \d+ Core \([\d,\- ]+\)$/.test(t)), cores.join(' | '));
    const cardText = await page.textContent('.xi-card');
    check(label + ': card shows CPU, TCP, RAM, threads, uptime', /CPU/.test(cardText) && /TCP connections/.test(cardText) && /RAM/.test(cardText) && /Threads/.test(cardText), cardText.slice(0, 200));
    // The panel scrolls an inner element, so shoot the viewport with the
    // section scrolled to the top of it.
    await page.$eval('.xi-summary', (e) => e.scrollIntoView({ block: 'start' }));
    await page.waitForTimeout(300);
    await page.screenshot({ path: `${SHOTS}/${label}-overview-instances.png` });
    const overlap = await page.evaluate(() => {
      const h = document.querySelector('.xi-summary').getBoundingClientRect();
      const c = document.querySelector('.xi-card').getBoundingClientRect();
      return h.bottom - c.top;
    });
    check(label + ': the first card sits below the summary', overlap <= 0, overlap + 'px overlap');
    if (label === 'desktop') {
      // Stop and start one instance from its card.
      const card = '.xi-card:has(.xi-name:text-is("xray-2"))';
      await page.click(`${card} .xi-stop`);
      await page.waitForSelector(`${card} .xi-start`, { timeout: 15000 });
      const stopped = await page.textContent(`${card} .xi-state`);
      check('desktop: Stop turns the card to Stopped with a Start button', /Stop/i.test(stopped), stopped);
      check('desktop: a stopped card has no Stop or Restart', !(await page.$(`${card} .xi-stop`)) && !(await page.$(`${card} .xi-restart`)));
      await page.click(`${card} .xi-start`);
      await page.waitForSelector(`${card} .xi-stop`, { timeout: 15000 });
      const started = await page.textContent(`${card} .xi-state`);
      check('desktop: Start brings it back to Running', /Running/.test(started), started);
    }
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
    const formOverflowX = await page.evaluate(() => {
      const b = document.querySelector('#inbound-modal .ant-modal-body');
      return b.scrollWidth - b.clientWidth;
    });
    await page.click('#inbound-modal .ant-modal-close');
    await page.waitForTimeout(400);

    // Multi Instance, from the row's menu.
    await page.click('.ant-table-row .anticon-more');
    await page.click('.ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item:has-text("Multi Instance")');
    await page.waitForSelector('#multi-instance-modal .mi-item', { timeout: 10000 });
    const items = await page.$$eval('#multi-instance-modal .mi-item .mi-port', (els) => els.map((e) => +e.textContent));
    check(label + ': multi instance previews the next port', items.length === 1, items.join(','));
    await page.click('#multi-instance-modal .ant-radio-button-wrapper:has-text("Fixed")');
    await page.click('#multi-instance-modal .ant-checkbox-wrapper');
    await page.waitForTimeout(900);
    const maxText = await page.textContent('#multi-instance-modal .ant-checkbox-wrapper');
    const maxN = +(maxText.match(/\((\d+)\)/) || [])[1];
    const listed = await page.$$eval('#multi-instance-modal .mi-item', (els) => els.length);
    check(label + ': Max fills the free cores with 1-core instances', maxN > 0 && listed === maxN, `max=${maxN} listed=${listed}`);
    await page.click('#multi-instance-modal .ant-checkbox-wrapper'); // back to a number
    await page.fill('#multi-instance-modal .mi-count input', '2');
    await page.waitForTimeout(900);
    const two = await page.$$eval('#multi-instance-modal .mi-item .mi-port', (els) => els.map((e) => +e.textContent));
    check(label + ': two instances on consecutive ports', two.length === 2 && two[1] === two[0] + 1, two.join(','));
    await (await page.$('#multi-instance-modal .ant-modal-content')).screenshot({ path: `${SHOTS}/${label}-multi-instance.png` });
    if (label === 'desktop') {
      const before = await page.$$eval('.ant-table-row', (els) => els.length);
      const off = await page.$eval('#multi-instance-modal .ant-modal-footer .ant-btn-primary', (b) => b.disabled);
      if (off) {
        const why = await page.textContent('#multi-instance-modal .mi-body');
        throw new Error('Generate is off: ' + why.replace(/\s+/g, ' ').slice(0, 400));
      }
      await page.click('#multi-instance-modal .ant-modal-footer .ant-btn-primary');
      await page.waitForSelector('#multi-instance-modal .ant-modal-wrap', { state: 'hidden', timeout: 20000 });
      await page.waitForTimeout(1500);
      const after = await page.$$eval('.ant-table-row', (els) => els.length);
      check('desktop: generate adds the inbounds', after === before + 2, `${before} -> ${after}`);
    } else {
      // The desktop pass already made these copies: the preview says so.
      const bad = await page.$$eval('#multi-instance-modal .mi-bad', (els) => els.length);
      const disabled = await page.$eval('#multi-instance-modal .ant-modal-footer .ant-btn-primary', (b) => b.disabled);
      check(label + ': taken ports are flagged and Generate is off', bad === 2 && disabled, `bad=${bad} disabled=${disabled}`);
      await page.click('#multi-instance-modal .ant-modal-close');
    }
    const formOverflow = formOverflowX;

    check(label + ': form has no horizontal scroll', formOverflow <= 0, formOverflow + 'px');
    await ctx.close();
  }
  check('no JS errors', errors.length === 0, errors.slice(0, 5).join(' | '));
  await browser.close();
  const failed = results.filter((r) => !r).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
})();
