'use strict';
// Loads only HTML/assets served by the packaged panel; no source render helper,
// local script injection, fake API response, or substituted clipboard handler.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const session=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),work=process.argv[3];
const origin=new URL(session.url).origin;
const checks=[],pageErrors=[],consoleErrors=[],blockedExternal=[],assets=new Set();
let browser,page;
const report={passed:false,checks,pageErrors,consoleErrors,blockedExternal,sourceTemplatesUsed:false};
async function visibleDialog(){await page.locator('.ant-modal:visible').waitFor({state:'visible'});}
async function closeDialog(){await page.locator('.ant-modal:visible .ant-modal-close').click();await page.waitForFunction(()=>!inModal.visible);await page.waitForTimeout(220);}
async function assertJsonResponse(response,label){assert.ok(response.ok(),label+' HTTP');const json=await response.json();assert.equal(json.success,true,label+': '+(json.msg||''));return json.obj;}
(async()=>{
 try{
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROME||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
  const context=await browser.newContext({viewport:{width:1440,height:1100},locale:'en-US',acceptDownloads:true});
  await context.addCookies(session.cookies);await context.grantPermissions(['clipboard-read','clipboard-write'],{origin});
  page=await context.newPage();
  await page.route('**/*',route=>{const url=new URL(route.request().url());if(url.protocol==='http:'||url.protocol==='https:'){if(url.origin!==origin){blockedExternal.push(url.origin+url.pathname);return route.abort();}}return route.continue();});
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text());});
  page.on('response',response=>{if(response.url().startsWith(origin)&&response.url().includes('/assets/'))assets.add(new URL(response.url()).pathname);});
  await page.goto(session.url+'/panel/inbounds');
  await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
  assert.equal(await page.evaluate(()=>app.dbInbounds.length),session.cases.length);
  await page.screenshot({path:path.join(work,'embedded-inbounds.png'),fullPage:true});
  checks.push({embeddedInboundsPage:true,rowCount:session.cases.length});
  for(const item of session.cases){
   // Actual shipped dialog, generated credential request and dynamic controls.
   await page.evaluate(()=>app.openAddInbound());await visibleDialog();
   await page.evaluate(protocol=>{inModal.inbound.protocol=protocol;},item.protocol);
   await page.waitForFunction(protocol=>inModal.inbound.protocol===protocol&&inModal.inbound.isNative,item.protocol);
   await page.waitForFunction(()=>!inModal.inbound.settings.generating&&!inModal.inbound.settings.modeDefaultsPending);
   assert.ok(await page.locator('.ant-modal:visible .ant-form-item').count()>3);
   const fields=await page.evaluate(()=>inModal.inbound.settings.fields.map(f=>f.path));
   assert.ok(fields.length>0);checks.push({protocol:item.protocol,newDialog:true,typedFieldCount:fields.length});
   await closeDialog();
   await page.evaluate(id=>app.openEditInbound(id),item.id);await visibleDialog();
   const timeout=page.locator('.ant-modal:visible .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'Handshake timeout (seconds)'})}).first().locator('input');
   await timeout.fill('19');await timeout.press('Tab');
   assert.deepEqual(await page.evaluate(()=>inModal.inbound.settings.validationErrors),[]);
   const saved=page.waitForResponse(r=>r.url().endsWith('/panel/api/inbounds/update/'+item.id)&&r.request().method()==='POST');
   await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();
   await assertJsonResponse(await saved,item.protocol+' inbound save');
   await page.waitForFunction(()=>!inModal.visible&&!app.loadingStates.spinning);
   await page.evaluate(()=>app.getDBInbounds());
   const row=page.locator('.ant-table-tbody').first().locator(':scope > tr.ant-table-row').filter({hasText:item.remark});
   const icon=row.locator('.ant-table-row-expand-icon');
   if(!await icon.evaluate(node=>node.classList.contains('ant-table-row-expanded')))await icon.click();
   const expanded=row.locator('xpath=following-sibling::tr[1]');
   const client=expanded.locator('tr.ant-table-row').filter({has:page.locator('.client-email').getByText(item.email,{exact:true})});
   await client.locator('.native-client-config-copy').waitFor({state:'visible'});
   const copied=page.waitForResponse(r=>r.url().endsWith('/panel/api/inbounds/'+item.id+'/clientConfig')&&r.request().method()==='POST');
   await page.bringToFront();await client.locator('.native-client-config-copy').click();
   const value=await assertJsonResponse(await copied,item.protocol+' selected JSON');
   assert.deepEqual(JSON.parse((await copied).request().postData()),{email:item.email});
   await page.waitForFunction(()=>app.nativeClientConfigBusy==='');
   let text;
   if(await page.locator('.ant-modal:visible .native-client-json-content').count()){
    text=await page.locator('.ant-modal:visible .native-client-json-content').inputValue();
    await page.locator('.ant-modal:visible .ant-modal-close').click();
   }else text=await page.evaluate(()=>navigator.clipboard.readText());
   assert.deepEqual(JSON.parse(text),value.config,'copied content equals real API response');
   fs.writeFileSync(path.join(work,'copied-'+item.protocol+'.json'),text,{mode:0o600});
   checks.push({protocol:item.protocol,typedEditSaved:true,actualCopyControl:true,selectedAccount:true,clipboardOrFallbackVerified:true});
  }
  // Load the package's Xray page and add exported native settings through its
  // actual modal callback, then click Save and reload persisted data.
  await page.goto(session.url+'/panel/xray');
  await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
  const expected=[];
  for(const item of session.cases){
   const config=JSON.parse(fs.readFileSync(path.join(work,'copied-'+item.protocol+'.json'),'utf8'));
   const native=config.outbounds.filter(o=>!['freedom','blackhole'].includes(o.protocol));
   const tags=new Map(native.map(o=>[o.tag,'embedded-'+item.protocol+'-'+o.tag]));
   for(const outbound of native){outbound.tag=tags.get(outbound.tag);if(outbound.proxySettings?.tag)outbound.proxySettings.tag=tags.get(outbound.proxySettings.tag);}
   // Carrier first makes the full chain available before the inner is saved.
   native.sort((a,b)=>(a.proxySettings?1:0)-(b.proxySettings?1:0));
   for(const outbound of native){
    await page.evaluate(outbound=>{app.addOutbound();outModal.outbound=Outbound.fromJson(outbound);outModal.isEdit=true;outModal.check();},outbound);
    await page.locator('.ant-modal:visible .ant-form').waitFor({state:'visible'});
    assert.equal(await page.evaluate(()=>outModal.isValid),true,item.protocol+' outbound valid');
    assert.ok(await page.locator('.ant-modal:visible .ant-form-item').count()>2);
    const serialized=await page.evaluate(()=>JSON.parse(JSON.stringify(outModal.outbound.toJson())));
    const semantic=structuredClone(serialized);
    if(outbound.streamSettings===undefined&&semantic.streamSettings!==undefined){
     // Legacy SS models already emit this no-op stream default. Require it to
     // be exact, and verify all original fields before accepting that addition.
     assert.deepEqual(semantic.streamSettings,{network:'tcp',security:'none',tcpSettings:{header:{type:'none'}}},'only default stream settings may be added');
     delete semantic.streamSettings;
    }
    assert.deepEqual(semantic,outbound,'outbound dialog must retain all exported protocol and chaining settings');
    await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();
    await page.waitForFunction(()=>!outModal.visible);
    expected.push(serialized);
    checks.push({protocol:item.protocol,outboundProtocol:outbound.protocol,embeddedOutboundDialog:true,actualModalOK:true});
   }
  }
  await page.waitForFunction(()=>!app.saveBtnDisable);
  const stored=page.waitForResponse(r=>r.url().endsWith('/panel/xray/update')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Save',exact:true}).click();
  await assertJsonResponse(await stored,'outbound template save');
  await page.waitForFunction(()=>app.saveBtnDisable&&!app.loadingStates.spinning);
  await page.reload();await page.waitForFunction(()=>app.loadingStates.fetched&&!app.loadingStates.spinning);
  const persisted=await page.evaluate(()=>app.templateSettings.outbounds);
  for(const outbound of expected)assert.deepEqual(persisted.find(o=>o.tag===outbound.tag),outbound,'persisted outbound '+outbound.tag);
  await page.screenshot({path:path.join(work,'embedded-outbounds.png'),fullPage:true});
  checks.push({embeddedOutboundTemplateSaveReload:true,outbounds:expected.length});
  assert.ok([...assets].some(url=>url.endsWith('/native-inbound.js')),'embedded native inbound asset loaded');
  assert.ok([...assets].some(url=>url.endsWith('/outbound.js')),'embedded outbound asset loaded');
  assert.deepEqual(pageErrors,[]);assert.deepEqual(consoleErrors,[]);
  report.passed=true;
 }catch(error){report.error=error.stack||String(error);if(page)await page.screenshot({path:path.join(work,'embedded-failure.png'),fullPage:true}).catch(()=>{});}
 finally{report.assets=[...assets].sort();fs.writeFileSync(path.join(work,'browser-results.json'),JSON.stringify(report,null,2),{mode:0o600});if(browser)await browser.close();}
 console.log(JSON.stringify({passed:report.passed,checks:checks.length,pageErrors,consoleErrors,report:path.join(work,'browser-results.json')}));
 process.exitCode=report.passed?0:1;
})();
