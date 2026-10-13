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
    if (label === 'desktop') {
      // Asset URLs carry a fingerprint of the assets, so a browser does not
      // keep last build's scripts (they are cached for a year).
      await page.goto(PANEL + '/panel/inbounds');
      const src = await page.$eval('script[src*="dbinbound.js"]', (e) => e.getAttribute('src'));
      check('desktop: asset URLs carry the assets fingerprint', /\?[^&]+-[0-9a-f]{10}$/.test(src), src);
    }

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
    const cut = await page.$$eval('.xi-card .xi-egress-ip, .xi-card .xi-udp', (els) => els.filter((e) => e.scrollWidth > e.clientWidth + 1).map((e) => e.textContent.trim()));
    check(label + ': outgoing IP and UDP ports are not cut off', cut.length === 0, cut.join(' | '));
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

      // Outgoing IP: the dialog lists the server's addresses, and one that
      // reaches nothing (this namespace has no route out) is refused.
      const card1 = '.xi-card:has(.xi-name:text-is("xray-1"))';
      const facts = await page.textContent(`${card1} .xi-facts`);
      check('desktop: card shows the outgoing IP and UDP ports', /Outgoing IP\s*Default/.test(facts) && /UDP ports\s*[\d.]+k? \/ [\d.]+k/.test(facts), facts.replace(/\s+/g, ' '));
      await page.click(`${card1} .xi-egress-edit`);
      await page.waitForSelector('#egress-modal .ant-select', { state: 'visible' });
      await page.click('#egress-modal .ant-select');
      const listed = await page.waitForSelector('.ant-select-dropdown-menu-item:has-text("1.2.3.4")', { timeout: 10000 }).then(() => true, () => false);
      check('desktop: the outgoing IP dialog lists the server addresses', listed);
      if (listed) {
        await page.click('.ant-select-dropdown-menu-item:has-text("1.2.3.4")');
        await page.click('#egress-modal .ant-btn-primary');
        const err = await page.waitForSelector('.ant-message-error', { timeout: 15000 }).then((e) => e.textContent(), () => '');
        check('desktop: an IP that reaches nothing is refused with a message', /outgoing IP/.test(err) && /answers/.test(err), err);
        check('desktop: the dialog stays open after a refusal', await page.isVisible('#egress-modal .ant-select'));
        await page.screenshot({ path: `${SHOTS}/desktop-egress.png` });
      }
      await page.click('#egress-modal .ant-modal-footer .ant-btn:not(.ant-btn-primary)');
      await page.waitForSelector('#egress-modal .ant-select', { state: 'hidden' });
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
    // No silent clamping: more than available is allowed in the box and
    // refused with a message.
    const box = '#inbound-modal .ant-form-item:has-text("CPU cores") .ant-input-number-input';
    if (m) {
      await page.fill(box, String(+m[2] + 1));
      await page.waitForTimeout(300);
      const kept = await page.inputValue(box);
      const tooMany = await page.$('#inbound-modal .xray-instance-error');
      check(label + ': more cores than available are kept and refused with a message', kept === String(+m[2] + 1) && !!tooMany, `value=${kept}`);
      await page.fill(box, '1');
    }
    await modal.screenshot({ path: `${SHOTS}/${label}-inbound-form.png` });
    // Typing an existing instance takes over its cores.
    await page.fill('#inbound-modal .ant-select-auto-complete input', 'xray-1');
    await page.waitForTimeout(300);
    // xray-1 is on auto until the desktop pass below fixes it at 3 cores.
    const mode = await page.$eval('#inbound-modal .ant-radio-button-wrapper-checked', (e) => e.textContent.trim());
    const want = label === 'desktop' ? 'Auto' : 'Fixed';
    const val = want === 'Fixed' ? await page.inputValue(box) : '';
    check(label + ': picking an existing instance takes its cores', mode === want && (want === 'Auto' || val === '3'), `${mode} ${val}`);
    const shared = await page.textContent('#inbound-modal .ant-form-item:has-text("Xray instance")');
    check(label + ': form lists the other inbounds of that instance', /Also runs:/.test(shared), shared.slice(0, 120));
    const formOverflowX = await page.evaluate(() => {
      const b = document.querySelector('#inbound-modal .ant-modal-body');
      return b.scrollWidth - b.clientWidth;
    });
    await page.click('#inbound-modal .ant-modal-close');
    await page.waitForTimeout(400);

    // Fixed cores: the saved number shows as saved, and clearing it while
    // typing does not switch to Auto.
    const openEdit = async () => {
      await page.click('.ant-table-row .anticon-more');
      await page.click('.ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item:has-text("Edit")');
      await page.waitForSelector('#inbound-modal .ant-modal-body', { timeout: 10000 });
      await page.waitForTimeout(900);
    };
    const coresBox = '#inbound-modal .ant-form-item:has-text("CPU cores") .ant-input-number-input';
    if (label === 'desktop') {
      await openEdit();
      await page.click('#inbound-modal .ant-form-item:has-text("CPU cores") .ant-radio-button-wrapper:has-text("Fixed")');
      await page.fill(coresBox, '3');
      await page.click('#inbound-modal .ant-modal-footer .ant-btn-primary');
      await page.waitForSelector('#inbound-modal .ant-modal-wrap', { state: 'hidden', timeout: 15000 });
      await page.waitForTimeout(800);
    }
    await openEdit();
    const shown = await page.inputValue(coresBox);
    check(label + ': saved fixed cores show as saved (3)', shown === '3', shown);
    if (label !== 'desktop') {
      // This inbound has sub-inbounds on instances of their own now: their
      // cores are not free.
      const info = await page.evaluate(async () => (await HttpUtil.get('/panel/api/inbounds/xrayInstances')).obj);
      const id = await page.evaluate(() => inModal.dbInbound.id);
      const own = info.instances.find((it) => it.inbounds.some((i) => i.id === id && !i.sub)).name;
      const others = info.instances.filter((it) => it.name !== own);
      const subCores = others.filter((it) => it.inbounds.some((i) => i.id === id && i.sub)).reduce((a, it) => a + it.cores, 0);
      const want = info.totalCores - others.reduce((a, it) => a + (it.cores > 0 ? it.cores : 0), 0) - (others.some((it) => !(it.cores > 0)) ? 1 : 0) - 3;
      const h = await page.textContent('#inbound-modal .xray-instance-hint');
      const got = +(h.match(/Available:\s*(\d+)/) || [])[1];
      check(label + ': available counts the sub-inbounds\' cores', subCores >= 2 && got === Math.max(0, want), `shown ${got}, want ${want} (subs hold ${subCores})`);
      await page.fill(coresBox, '4');
      await page.waitForTimeout(300);
      const got4 = +((await page.textContent('#inbound-modal .xray-instance-hint')).match(/Available:\s*(\d+)/) || [])[1];
      check(label + ': available follows the number typed', got4 === Math.max(0, want - 1), `${got} -> ${got4}`);
    }
    await page.fill(coresBox, '');
    await page.waitForTimeout(300);
    const modeAfter = await page.$eval('#inbound-modal .ant-form-item:has-text("CPU cores") .ant-radio-button-wrapper-checked', (e) => e.textContent.trim());
    const emptyMsg = await page.$('#inbound-modal .xray-instance-error');
    check(label + ': clearing the number keeps Fixed and asks for a number', modeAfter === 'Fixed' && !!emptyMsg, modeAfter);
    await page.click('#inbound-modal .ant-modal-close');
    await page.waitForTimeout(400);

    // Multi Instance: sub-inbounds of the first inbound.
    const rowsBefore = await page.$$eval('.ant-table-row', (els) => els.length);
    await page.click('.ant-table-row .anticon-more');
    await page.click('.ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item:has-text("Multi Instance")');
    await page.waitForSelector('#multi-instance-modal .mi-body', { timeout: 10000 });
    await page.waitForTimeout(700);
    if (label === 'desktop') {
      check('desktop: no sub-inbounds yet', !!(await page.$('#multi-instance-modal .mi-empty')));
      const bodyText = await page.textContent('#multi-instance-modal .ant-modal-body');
      check('desktop: no long description in the dialog', !/each in its own xray instance/.test(bodyText) && bodyText.length < 200, bodyText.length + ' chars');
      // 1 core per instance, from the cores dropdown
      await page.click('#multi-instance-modal .mi-add-cores');
      await page.click('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-dropdown-menu-item:text-is("1 Core")');
      await page.fill('#multi-instance-modal .mi-count input', '2');
      await page.click('#multi-instance-modal .mi-add-btn');
      await page.waitForSelector('#multi-instance-modal .mi-row.mi-new', { timeout: 10000 });
      const ports = await page.$$eval('#multi-instance-modal .mi-row:not(.mi-row-head) .mi-port input', (els) => els.map((e) => +e.value));
      check('desktop: Add puts two sub-inbounds on the next ports', ports.length === 2 && ports[1] === ports[0] + 1, ports.join(','));
      await page.click('#multi-instance-modal .mi-max');
      await page.waitForTimeout(900);
      const maxText = await page.textContent('#multi-instance-modal .mi-max');
      check('desktop: Max shows how many more fit', /\(\d+\)/.test(maxText), maxText);
      await page.click('#multi-instance-modal .mi-max');
      await (await page.$('#multi-instance-modal .ant-modal-content')).screenshot({ path: `${SHOTS}/${label}-multi-instance.png` });
      await page.click('#multi-instance-modal .mi-save');
      await page.waitForSelector('#multi-instance-modal .ant-modal-wrap', { state: 'hidden', timeout: 20000 });
      await page.waitForTimeout(1500);
      const rowsAfter = await page.$$eval('.ant-table-row', (els) => els.length);
      check('desktop: sub-inbounds add no inbounds', rowsAfter === rowsBefore, `${rowsBefore} -> ${rowsAfter}`);
      const subTag = await page.$$eval('.ant-table-row .sub-count', (els) => els.map((e) => e.textContent.trim()));
      check('desktop: the inbound shows +2', subTag.includes('+2'), subTag.join(','));
    } else {
      const rows = await page.$$eval('#multi-instance-modal .mi-row:not(.mi-row-head)', (els) => els.length);
      check(label + ': the dialog lists the saved sub-inbounds', rows === 2, rows);
      const insts = await page.$$eval('#multi-instance-modal .mi-c-inst input', (els) => els.map((e) => e.value));
      const fit = await page.evaluate(() => {
        const q = (sel) => document.querySelector('#multi-instance-modal ' + sel).getBoundingClientRect();
        const cut = [...document.querySelectorAll('#multi-instance-modal .ant-select-selection-selected-value, #multi-instance-modal .mi-inst')]
          .filter((e) => e.scrollWidth > e.clientWidth + 1).map((e) => e.textContent || e.value);
        return { cut, sameLine: Math.abs(q('.mi-add-btn').top - q('.mi-count').top) < 4 };
      });
      check(label + ': no cut-off text in the rows', fit.cut.length === 0, JSON.stringify(fit.cut));
      check(label + ': Add sits beside the count', fit.sameLine);
      check(label + ': each has its own instance', insts.length === 2 && insts[0] !== insts[1] && insts.every((n) => /^xray-\d+$/.test(n)), insts.join(','));
      const dialogOverflow = await page.evaluate(() => {
        const b = document.querySelector('#multi-instance-modal .ant-modal-body');
        return b.scrollWidth - b.clientWidth;
      });
      check(label + ': dialog has no horizontal scroll', dialogOverflow <= 0, dialogOverflow + 'px');
      await (await page.$('#multi-instance-modal .ant-modal-content')).screenshot({ path: `${SHOTS}/${label}-multi-instance.png` });
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
