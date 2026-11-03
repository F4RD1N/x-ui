'use strict';
// Tests the actual local inbound templates and Vue controls; no live panel/API traffic.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-inbound-ui-'));
const file = relative => pathToFileURL(path.join(root, relative)).href;
const templates = new Map();
function walk(dir) {
  for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
    const filename = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(filename);
    else if (filename.endsWith('.html')) {
      const html = fs.readFileSync(filename, 'utf8');
      const match = html.match(/{{\s*define\s+"([^"]+)"\s*}}([\s\S]*){{\s*end\s*}}/);
      if (match) templates.set(match[1], match[2]);
    }
  }
}
walk(path.join(root, 'web/html'));
function render(name) {
  if (!templates.has(name)) throw new Error('Missing template ' + name);
  return templates.get(name).replace(/{{\s*template\s+"([^"]+)"(?:\s+\.)?\s*}}/g, (_, child) => render(child)).replace(/{{\s*i18n\s+"([^"]+)"\s*}}/g, '$1');
}
const html = `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="${file('web/assets/ant-design-vue/antd.min.css')}"></head><body>
<script src="${file('web/assets/vue/vue.min.js')}"></script><script src="${file('web/assets/moment/moment.min.js')}"></script><script src="${file('web/assets/ant-design-vue/antd.min.js')}"></script><script src="${file('web/assets/js/util/index.js')}"></script><script src="${file('web/assets/js/model/inbound.js')}"></script><script src="${file('web/assets/js/model/native-inbound.js')}"></script><script src="${file('web/assets/js/model/dbinbound.js')}"></script>
<script>const basePath='/fixture-prefix/'; window.themeSwitcher={currentTheme:'light'}; window.app={datepicker:'gregorian',subSettings:{enable:false},tgBotEnable:false,ipLimitEnable:false,$message:Vue.prototype.$message}; Vue.config.productionTip=false;</script>
${render('modals/inboundModal')}</body></html>`;
const fixtureFile = path.join(temp, 'fixture.html');
fs.writeFileSync(fixtureFile, html);
const uuid = '11111111-2222-4333-8444-555555555555';
const pem = '-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----';
const fixtures = {
  anytls: {clients: [{password: 'synthetic-password', email: 'anytls'}], handshakeTimeout: 10, maxStreams: 128},
  mieru: {clients: [{username: uuid, password: 'synthetic-password', email: 'mieru'}], transport: 'tcp', handshakeTimeout: 10},
  dnstt: {domain: 'tunnel.example', privateKey: '11'.repeat(32), inner: {protocol: 'vless'}, clients: [{id: uuid, email: 'dnstt'}], mtu: 1232, handshakeTimeout: 30},
  openvpn: {network: 'tcp', certificates: {ca: pem, cert: pem, key: '-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----'}, clients: [{commonName: 'synthetic-client', email: 'openvpn', certificate:pem,privateKey:'CLIENT KEY'}], limits: {handshakeSeconds: 15}},
  shadowtls: {version: 3, strict: true, handshake: {address: 'tls.example', port: 443}, handshakeTimeout: 10, clients: [{password: uuid, email: 'shadowtls'}], inner: {protocol: 'socks', settings: {auth: 'password', accounts: [{user: 'synthetic', pass: 'synthetic'}], udp: false}}},
  orbit: {transport: 'tcp', handshakeTimeout: 15, tls: {certificate: pem.split('\n'), key: ['-----BEGIN PRIVATE KEY-----', 'SYNTHETIC', '-----END PRIVATE KEY-----']}, clients: [{key: 'vck1_' + 'A'.repeat(86), email: 'orbit'}]},
};
(async () => {
  let browser;
  const errors = [], checks = [];
  try {
    browser = await chromium.launch({headless:true, executablePath:process.env.CHROME || undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page = await browser.newPage();
    page.on('pageerror', error => { errors.push(error.message); console.error(error.message); });
    page.on('console', message => {if (message.type() === 'error') errors.push(message.text());});
    await page.goto(pathToFileURL(fixtureFile).href);
    await page.waitForFunction(() => typeof Inbound !== 'undefined' && typeof inModal !== 'undefined');
    for (const [layout,width,height,theme] of [['desktop',1366,900,'light'],['mobile',390,844,'dark']]) {
      await page.setViewportSize({width,height});
      for (const [protocol,settings] of Object.entries(fixtures)) {
        await page.evaluate(({protocol,settings,theme}) => {
          themeSwitcher.currentTheme=theme;
          const inbound=Inbound.fromJson({protocol,settings:{...settings,futureOption:{retain:true}},port:18080,streamSettings:protocol==='anytls'?{network:'tcp',security:'tls'}:undefined});
          inModal.show({inbound,isEdit:true});
        }, {protocol,settings,theme});
        await page.waitForSelector('.ant-modal-body .ant-alert-info');
        const item = page.locator('.ant-modal-body .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'Handshake timeout (seconds)'})}).first();
        await item.locator('input').fill('20');
        await item.locator('input').press('Tab');
        const output=await page.evaluate(() => inModal.inbound.settings.toJson());
        assert.equal(protocol==='openvpn'?output.limits.handshakeSeconds:output.handshakeTimeout,20,protocol+' typed timeout edit');
        assert.deepEqual(output.futureOption,{retain:true});
        {
          const header=page.locator('.ant-collapse-header').filter({hasText:'Client 1:'}).first();
          if (!(await header.evaluate(element=>element.parentElement.classList.contains('ant-collapse-item-active')))) await header.click();
        }
        const emailItem=page.locator('.ant-modal-body .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'pages.inbounds.email'})}).first();
        await emailItem.locator('input').fill('edited-'+protocol);
        await emailItem.locator('input').press('Tab');
        assert.equal(await page.evaluate(() => inModal.inbound.clients[0].email),'edited-'+protocol);
        await page.evaluate(() => {const s=inModal.inbound.settings; s.advancedJSON=JSON.stringify(s.toJson());});
        assert.deepEqual(await page.evaluate(() => inModal.inbound.settings.validationErrors),[],protocol+' roundtrip validates');
        await page.evaluate(() => {window.submitted=0;inModal.confirm=()=>window.submitted++;inModal.ok();});
        assert.equal(await page.evaluate(() => window.submitted),1,protocol+' saves once');
        checks.push({layout,protocol,typedEdit:true,clientEdit:true,jsonRoundTrip:true,save:true});
      }
    }
    for (const [protocol,label,flag,settings] of [
      ['vmess','Raw UUID authentication compatibility','rawUuidAuth',{clients:[{id:uuid,email:'vmess-auth'}]}],
      ['trojan','UUID hash prefix compatibility','uuidHashPrefix',{clients:[{password:uuid,email:'trojan-auth'}]}],
      ['shadowsocks','UUID identity key import compatibility','uuidIdentityKeys',{method:'2022-blake3-aes-128-gcm',password:'MTIzNDU2Nzg5MDEyMzQ1Ng==',clients:[{password:uuid,email:'ss-auth'}]}],
    ]) {
      await page.evaluate(({protocol,settings}) => {inModal.show({inbound:Inbound.fromJson({protocol,settings,port:18080}),isEdit:false});}, {protocol,settings});
      const control=page.locator('.ant-modal-body .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:label})}).first();
      if (!(await control.isVisible())) await page.locator('.ant-collapse-header').first().click();
      await control.locator('button[role="switch"]').click();
      assert.equal(await page.evaluate(flag=>inModal.inbound.settings.toJson().clients[0][flag],flag),true);
      await page.evaluate(()=>{window.submitted=0;inModal.confirm=()=>window.submitted++;inModal.ok();});
      assert.equal(await page.evaluate(()=>window.submitted),1);
      checks.push({protocol,compatibilityControl:true});
    }
    await page.evaluate(settings=>{inModal.show({inbound:Inbound.fromJson({protocol:'dnstt',settings,port:18080}),isEdit:true});},fixtures.dnstt);
    const resolverControl=page.locator('.ant-modal-body .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'Client DNS resolvers JSON'})}).first();
    await resolverControl.locator('textarea').fill('[{"transport":"udp","address":"127.0.0.1:5353"}]');
    await resolverControl.locator('textarea').press('Tab');
    assert.deepEqual(await page.evaluate(()=>inModal.inbound.settings.toJson().clientExport.resolvers),[{transport:'udp',address:'127.0.0.1:5353'}]);
    checks.push({dnsttExportResolverEditor:true});
    await page.evaluate(() => {
      window.generationCalls=[];
      window.fetch=async (url,options)=>{
        const payload=JSON.parse(options.body); window.generationCalls.push({url,payload,headers:options.headers,credentials:options.credentials});
        const obj=payload.kind==='dnstt'?{privateKey:'44'.repeat(32),publicKey:'55'.repeat(32)}:payload.kind==='orbit'?{key:'vck1_'+'B'.repeat(86)}:payload.kind==='openvpn-proof'?{keyId:'proof-test',key:'66'.repeat(32)}:payload.kind==='openvpn-tls-crypt-v2-server'?{serverKey:'-----BEGIN OpenVPN tls-crypt-v2 server key-----\\nSYNTHETIC\\n-----END OpenVPN tls-crypt-v2 server key-----'}:{clientKey:'-----BEGIN OpenVPN tls-crypt-v2 client key-----\\nSYNTHETIC\\n-----END OpenVPN tls-crypt-v2 client key-----'};
        return {ok:true,json:async()=>({success:true,obj})};
      };
    });
    await page.getByRole('button',{name:'Generate new DNSTT key pair',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    assert.equal(await page.evaluate(()=>inModal.inbound.settings.toJson().privateKey),'44'.repeat(32));
    await page.evaluate(settings=>{inModal.show({inbound:Inbound.fromJson({protocol:'openvpn',settings,port:18080}),isEdit:true});},fixtures.openvpn);
    await page.getByRole('button',{name:'Generate new TLS-crypt-v2 server key',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    {
          const header=page.locator('.ant-collapse-header').filter({hasText:'Client 1:'}).first();
          if (!(await header.evaluate(element=>element.parentElement.classList.contains('ant-collapse-item-active')))) await header.click();
        }
    await page.getByRole('button',{name:'Generate new client proof key',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    await page.getByRole('button',{name:'Generate client TLS-crypt-v2 key',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    assert.equal(await page.evaluate(()=>inModal.inbound.clients[0].toJson().clientProof.key),'66'.repeat(32));
    assert.match(await page.evaluate(()=>inModal.inbound.clients[0].toJson().tlsCryptV2),/BEGIN OpenVPN/);
    await page.evaluate(settings=>{inModal.show({inbound:Inbound.fromJson({protocol:'orbit',settings,port:18080}),isEdit:true});},fixtures.orbit);
    {
          const header=page.locator('.ant-collapse-header').filter({hasText:'Client 1:'}).first();
          if (!(await header.evaluate(element=>element.parentElement.classList.contains('ant-collapse-item-active')))) await header.click();
        }
    await page.getByRole('button',{name:'Generate new Orbit client key',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    assert.equal(await page.evaluate(()=>inModal.inbound.clients[0].toJson().key),'vck1_'+'B'.repeat(86));
    const calls=await page.evaluate(()=>window.generationCalls);
    assert.equal(calls.length,5);
    for(const call of calls) {assert.equal(call.url,'/fixture-prefix/panel/api/server/native/credentials');assert.equal(call.headers['Content-Type'],'application/json');assert.equal(call.credentials,'same-origin');}
    assert.equal(calls[4].payload.certificate,pem);
    assert.match(calls[3].payload.serverKey,/BEGIN OpenVPN/);
    await page.evaluate(()=>{window.fetch=async()=>({ok:false});});
    await page.getByRole('button',{name:'Generate new Orbit client key',exact:true}).click();
    await page.waitForFunction(()=>!inModal.inbound.settings.generating);
    assert.equal(await page.evaluate(()=>inModal.inbound.clients[0].toJson().key),'vck1_'+'B'.repeat(86));
    assert.ok(await page.evaluate(()=>inModal.inbound.settings.generationError));
    checks.push({credentialGenerationButtons:5,jsonPayload:true,customBasePath:true,failurePreservesCredentials:true});
    await page.evaluate(() => {inModal.inbound.settings.advancedJSON='{broken';window.submitted=0;inModal.confirm=()=>window.submitted++;inModal.ok();});
    assert.equal(await page.evaluate(() => window.submitted),0);
    assert.ok((await page.evaluate(() => inModal.inbound.settings.validationErrors)).length);
    checks.push({malformedJSON:'rejected',staleSubmission:'prevented'});
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({passed:true,checks,pageErrors:errors},null,2));
  } finally {if (browser) await browser.close();fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
