'use strict';
// Complete Go-rendered page and actual Vue controls; only HTTP/WebSocket peers are fixtures.
// Synthetic PEM/keys test UI behavior only. Backend tests independently validate cryptography.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http');
const {execFileSync} = require('node:child_process');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-native-defaults-ui-'));
const helper = path.join(temp, 'render.go');
fs.writeFileSync(helper, `package main
import("html/template";"os";"path/filepath";"strings")
func main(){root:=os.Args[1];t:=template.New("").Funcs(template.FuncMap{"i18n":func(key string,args ...string)string{return key}});err:=filepath.WalkDir(filepath.Join(root,"web/html"),func(p string,d os.DirEntry,e error)error{if e!=nil{return e};if d.IsDir()||!strings.HasSuffix(p,".html"){return nil};b,e:=os.ReadFile(p);if e!=nil{return e};_,e=t.New(filepath.Base(p)).Parse(string(b));return e});if err!=nil{panic(err)};err=t.ExecuteTemplate(os.Stdout,"inbounds.html",map[string]any{"base_path":"/fixture/","cur_ver":"test","host":"127.0.0.1","title":"menu.inbounds","request_uri":"/fixture/panel/inbounds","lang":"en-US"});if err!=nil{panic(err)}}
`);
const rendered = execFileSync('go', ['run', helper, root], {encoding:'utf8', maxBuffer:8 << 20, env:{...process.env,GOMAXPROCS:'2'}});
const uuid = '11111111-2222-4333-8444-555555555555';
const pem = '-----BEGIN CERTIFICATE-----\nSYNTHETIC UI FIXTURE\n-----END CERTIFICATE-----';
const key = '-----BEGIN PRIVATE KEY-----\nSYNTHETIC UI FIXTURE\n-----END PRIVATE KEY-----';
const wrap = kind => '-----BEGIN OpenVPN tls-crypt-v2 '+kind+' key-----\nSYNTHETIC UI FIXTURE\n-----END OpenVPN tls-crypt-v2 '+kind+' key-----';
function profile(request, serial) {
  const client = {email:request.email || 'fixture@example.invalid',level:0,enable:true,subId:'server-sub-'+serial};
  const settings = {clients:[client]}, result = {protocol:request.protocol,settings};
  switch (request.protocol) {
    case 'anytls':
      Object.assign(client,{password:uuid}); Object.assign(settings,{handshakeTimeout:10,maxStreams:128,clientExport:{serverName:request.serverName,ca:pem}});
      result.streamSettings={network:'tcp',security:'tls',tlsSettings:{minVersion:'1.2',certificates:[{certificate:pem.split('\n'),key:key.split('\n')}]}}; break;
    case 'orbit':
      Object.assign(client,{key:'vck1_'+'A'.repeat(86)}); Object.assign(settings,{transport:'tcp',handshakeTimeout:15,maxSessions:1000,maxFlows:128,udpIdleTimeout:60,tls:{certificate:pem.split('\n'),key:key.split('\n')},clientExport:{serverName:request.serverName}}); break;
    case 'openvpn':
      Object.assign(client,{commonName:'client-'+uuid,certificate:pem,privateKey:key,tlsCryptV2:wrap('client')});
      Object.assign(settings,{network:'udp',certificates:{ca:pem,cert:pem,key,tlsCryptV2:wrap('server')},crypto:{dataCiphers:['AES-256-GCM','AES-128-GCM','CHACHA20-POLY1305'],authHash:'SHA256'},tunnel:{ipv4:'10.88.0.0/24',dns:['1.1.1.1'],mtu:1400},limits:{maxSessions:128,maxSessionsPerIP:16,maxFlowsPerSession:256,handshakeSeconds:15,idleSeconds:120},renegotiationSeconds:3600}); break;
    case 'mieru':
      Object.assign(client,{username:uuid,password:'22222222-3333-4444-8555-666666666666'}); Object.assign(settings,{transport:'tcp',handshakeTimeout:10}); break;
    case 'dnstt':
      Object.assign(client,{id:uuid}); Object.assign(settings,{domain:request.domain || 'fixture-'+serial+'.tunnel.invalid',privateKey:'11'.repeat(32),inner:{protocol:'vless'},mtu:1232,handshakeTimeout:30,maxSessions:256,maxStreams:128});
      result.publicKey='22'.repeat(32); break;
    case 'shadowtls':
      Object.assign(client,{password:uuid}); Object.assign(settings,{version:3,strict:true,handshakeTimeout:10,handshake:{address:request.handshakeAddress || 'www.microsoft.com',port:443},inner:{protocol:'shadowsocks',settings:{network:'tcp',method:'2022-blake3-aes-256-gcm',password:Buffer.alloc(32,1).toString('base64'),clients:[{email:client.email,level:0,password:Buffer.alloc(32,2).toString('base64')}]}}}); break;
    default: throw new Error('Unexpected profile protocol '+request.protocol);
  }
  return result;
}
const requests=[], submissions=[], deferred=[], checks=[];
let mode='ok', dataset=[], browser;
function json(res, body) { if (!res.destroyed) {res.setHeader('Content-Type','application/json');res.end(JSON.stringify(body));} }
function parseBody(req, text) {
  if (req.headers['content-type']?.includes('application/json')) return JSON.parse(text);
  if (req.headers['content-type']?.includes('multipart/form-data')) {
    const result={}; for (const part of text.split(/--[^\r\n]+\r\n/)) {const m=part.match(/name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n$/);if(m)result[m[1]]=m[2];}return result;
  }
  return Object.fromEntries(new URLSearchParams(text));
}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://127.0.0.1');
  if(url.pathname==='/fixture/panel/inbounds'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(rendered);return;}
  if(url.pathname.startsWith('/fixture/assets/')){
    const file=path.resolve(root,'web',url.pathname.slice('/fixture/'.length));
    if(!file.startsWith(path.join(root,'web/assets')+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
    res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');fs.createReadStream(file).pipe(res);return;
  }
  let text='';for await(const chunk of req)text+=chunk;
  if(url.pathname==='/fixture/panel/api/server/native/credentials'){
    const body=parseBody(req,text),serial=requests.length+1;requests.push({body,method:req.method,headers:req.headers});
    assert.equal(body.kind,'inbound-profile');
    const obj=profile(body,serial);
    if(mode==='hold'){deferred.push(()=>json(res,{success:true,obj}));return;}
    if(mode==='network'){req.socket.destroy();return;}
    if(mode==='malformed')obj.settings.clients=[];
    if(mode==='wrong-protocol')obj.protocol='vmess';
    if(mode==='bad-anytls')delete obj.streamSettings;
    setTimeout(()=>json(res,{success:true,obj}),35);return;
  }
  if(/\/panel\/api\/inbounds\/(add|update\/\d+|import)$/.test(url.pathname)){
    submissions.push({path:url.pathname,data:parseBody(req,text)});json(res,{success:true,obj:null});return;
  }
  let obj;
  if(url.pathname.endsWith('/panel/api/inbounds/list'))obj=dataset;
  else if(url.pathname.endsWith('/panel/api/inbounds/onlines'))obj=[];
  else if(url.pathname.endsWith('/panel/api/inbounds/lastOnline'))obj={};
  else if(url.pathname.endsWith('/panel/setting/defaultSettings'))obj={expireDiff:0,trafficDiff:0,defaultCert:'',defaultKey:'',tgBotEnable:false,subEnable:true,subTitle:'Fixture',subURI:'https://subscriptions.example.invalid/sub/',subJsonURI:'https://subscriptions.example.invalid/json/',subJsonEnable:true,pageSize:25,remarkModel:'-ieo',datepicker:'gregorian',ipLimitEnable:false};
  else if(url.pathname.endsWith('/panel/api/server/status'))obj={xray:{state:'running'}};
  else if(url.pathname==='/favicon.ico'){res.writeHead(204);res.end();return;}
  else{res.writeHead(404);res.end('Unexpected fixture request '+url.pathname);return;}
  json(res,{success:true,obj});
});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(predicate,label){for(let i=0;i<100;i++){if(predicate())return;await pause(50);}throw new Error('Timed out: '+label);}
function field(page,label){return page.locator('.ant-modal:visible .ant-form-item').filter({has:page.locator('.ant-form-item-label').filter({hasText:new RegExp('^\\s*'+label.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*$')})}).first();}
async function choose(page,protocol){await field(page,'protocol').locator('.ant-select').click();await page.locator('.ant-select-dropdown:visible .ant-select-dropdown-menu-item').getByText(protocol,{exact:true}).click();await page.waitForFunction(protocol=>inModal.inbound.protocol===protocol,protocol);}
async function open(page){await page.getByRole('button',{name:/pages\.inbounds\.addInbound$/}).click();await page.locator('.ant-modal:visible').waitFor({state:'visible'});}
async function close(page){await page.locator('.ant-modal:visible .ant-modal-close').click();await page.waitForFunction(()=>!inModal.visible);await page.waitForTimeout(220);}
async function ready(page){await page.waitForFunction(()=>inModal.inbound.isNative&&!inModal.inbound.settings.generating&&(inModal.inbound.settings.generationNotice||inModal.inbound.settings.generationError));}
function saveButton(page){return page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary');}
function dbRow(protocol='mieru'){
  const generated=profile({protocol,email:'saved@example.invalid',serverName:'saved.example.invalid',domain:'saved.example.invalid'},99);
  generated.settings.futureOption={retain:'saved'};
  return {id:91,userId:1,up:0,down:0,allTime:0,total:0,remark:'Saved native',enable:true,expiryTime:0,listen:'127.0.0.1',port:29091,protocol,settings:JSON.stringify(generated.settings),streamSettings:JSON.stringify(generated.streamSettings||{network:'tcp',security:'none'}),tag:'inbound-91',sniffing:'{}',clientStats:[],trafficReset:'never',lastTrafficResetTime:0};
}
(async()=>{
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROME||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[],consoleErrors=[];
  page.on('pageerror',error=>errors.push(error.message));page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text());});
  await page.addInitScript(()=>{localStorage.setItem('isRefreshEnabled','false');window.WebSocket=class{static OPEN=1;static CLOSED=3;constructor(){this.readyState=1;setTimeout(()=>this.onopen?.({}),10);}send(){}close(){this.readyState=3;}};});
  await page.goto('http://127.0.0.1:'+server.address().port+'/fixture/panel/inbounds');
  await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
  await open(page);await page.waitForTimeout(120);
  const defaultProtocol=await page.evaluate(()=>inModal.inbound.protocol);
  assert.equal(await page.evaluate(()=>inModal.inbound.isNative),false);await choose(page,'vmess');await page.waitForTimeout(80);assert.equal(requests.length,0,'VMess must not request native material');await close(page);
  checks.push({defaultVmessNoGeneration:true});
  for(const protocol of ['orbit','dnstt','openvpn','anytls','shadowtls','mieru']){
    mode='hold';await open(page);const before=requests.length;await choose(page,protocol);await until(()=>requests.length===before+1,protocol+' request');
    assert.equal(await saveButton(page).isDisabled(),true,protocol+' save disabled during generation');
    const original=await page.evaluate(()=>inModal.inbound.clients[0]._clientBaseToJson());
    deferred.shift()();await ready(page);
    const state=await page.evaluate(()=>({settings:inModal.inbound.settings.toJson(),stream:inModal.inbound.stream.toJson(),errors:inModal.inbound.settings.validationErrors,error:inModal.inbound.settings.generationError,publicKey:inModal.inbound.settings.generatedPublicKey}));
    assert.equal(state.error,'',protocol+' valid response applied');
    for(const [name,value] of Object.entries(original))assert.deepEqual(state.settings.clients[0][name],value,protocol+' client metadata '+name+' retained');
    assert.equal(requests.at(-1).body.email,original.email);assert.equal(requests.at(-1).body.serverName,'127.0.0.1');
    if(protocol==='dnstt'){
      assert.equal(state.settings.privateKey,'11'.repeat(32));assert.equal(state.publicKey,'22'.repeat(32));
      assert.match(state.settings.domain,/\.tunnel\.invalid$/);
    }
    assert.deepEqual(state.errors,[],protocol+' generated validation');
    if(protocol==='anytls'){assert.equal(state.stream.security,'tls');assert.ok(state.stream.tlsSettings.certificates[0].certificate.length);}
    if(protocol==='openvpn'){assert.match(state.settings.certificates.tlsCryptV2,/server key/);assert.match(state.settings.clients[0].tlsCryptV2,/client key/);assert.equal(state.settings.clients[0].certificate,pem);}
    if(protocol==='shadowtls'){assert.equal(state.settings.inner.protocol,'shadowsocks');assert.equal(state.settings.inner.settings.clients[0].email,state.settings.clients[0].email);}
    const saved=submissions.length;await saveButton(page).click();await until(()=>submissions.length===saved+1,protocol+' real create click');
    const payload=submissions.at(-1);assert.equal(payload.path,'/fixture/panel/api/inbounds/add');assert.equal(payload.data.protocol,protocol);const submitted=JSON.parse(payload.data.settings);assert.equal(submitted.clients[0].email,original.email);
    assert.equal(Object.hasOwn(submitted,'needsProfile'),false);assert.equal(Object.hasOwn(submitted,'generationNotice'),false);
    await page.waitForFunction(()=>!inModal.visible);await page.waitForTimeout(220);assert.equal(requests.length,before+1,protocol+' no extra generation');checks.push({protocol,automaticDefaults:true,pendingSaveDisabled:true,metadataPreserved:true,realCreate:true});
  }
  // Edit, import-shaped modal, and clone must retain stored keys and unknown metadata.
  mode='ok';dataset=[dbRow()];await page.evaluate(()=>app.getDBInbounds());const preserveBefore=requests.length;
  await page.evaluate(()=>app.openEditInbound(91));await page.waitForTimeout(100);
  assert.equal(await field(page,'protocol').locator('.ant-select').evaluate(el=>el.classList.contains('ant-select-disabled')),true);
  assert.deepEqual(await page.evaluate(()=>inModal.inbound.settings.toJson().futureOption),{retain:'saved'});assert.equal(requests.length,preserveBefore);await close(page);
  await page.evaluate(row=>inModal.show({inbound:new DBInbound(row).toInbound(),isEdit:false}),dataset[0]);await page.waitForTimeout(100);
  assert.equal(requests.length,preserveBefore,'prepopulated imported inbound must not generate');assert.deepEqual(await page.evaluate(()=>inModal.inbound.settings.toJson().futureOption),{retain:'saved'});await close(page);
  await page.getByRole('button',{name:/pages\.inbounds\.generalActions$/}).click();await page.locator('.ant-dropdown:visible .ant-dropdown-menu').last().getByText('pages.inbounds.importInbound',{exact:true}).click();
  const importedText=JSON.stringify(dataset[0]);await page.locator('#prompt-modal-input').fill(importedText);const beforeImport=submissions.length;await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await until(()=>submissions.length===beforeImport+1,'real import click');
  assert.equal(submissions.at(-1).path,'/fixture/panel/api/inbounds/import');assert.equal(submissions.at(-1).data.data,importedText);assert.equal(requests.length,preserveBefore,'actual import must not generate');await page.waitForFunction(()=>!promptModal.visible);await page.waitForTimeout(220);
  const beforeClone=submissions.length;await page.evaluate(()=>{const row=app.dbInbounds.find(row=>row.id===91);return app.cloneInbound(row.toInbound(),row);});await until(()=>submissions.length===beforeClone+1,'clone submission');assert.equal(requests.length,preserveBefore);const cloned=JSON.parse(submissions.at(-1).data.settings);assert.deepEqual(cloned.futureOption,{retain:'saved'});assert.equal(cloned.clients[0].username,uuid);assert.notEqual(cloned.clients[0].email,'saved@example.invalid');checks.push({editImportClonePreserved:true,noGeneration:true});
  // A late server reply must not overwrite another protocol or a closed/new form.
  mode='hold';await open(page);await choose(page,'orbit');await until(()=>deferred.length===1,'pending switch');await choose(page,'vmess');deferred.shift()();await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>inModal.inbound.protocol),'vmess');await close(page);
  await open(page);await choose(page,'openvpn');await until(()=>deferred.length===1,'pending close');await close(page);deferred.shift()();await open(page);await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>inModal.inbound.protocol),defaultProtocol);assert.equal(await page.evaluate(()=>inModal.inbound.isNative),false);await close(page);checks.push({lateSwitchIgnored:true,lateCloseIgnored:true});
  await open(page);await choose(page,'orbit');await until(()=>deferred.length===1,'pending native switch');await choose(page,'anytls');await until(()=>deferred.length===2,'second native request');deferred.shift()();await page.waitForTimeout(80);assert.equal(await page.evaluate(()=>inModal.inbound.protocol),'anytls');assert.equal(await page.evaluate(()=>inModal.inbound.settings.generating),true);deferred.shift()();await ready(page);assert.equal(await page.evaluate(()=>inModal.inbound.stream.security),'tls');assert.equal(await page.evaluate(()=>inModal.inbound.settings.toJson().clients[0].key),undefined);await close(page);checks.push({lateNativeSwitchIgnored:true});
  // Safe edits merge with fresh credentials; intentional credential edits are never overwritten.
  for(const protocol of ['mieru','shadowtls']){
    await open(page);await choose(page,protocol);await until(()=>deferred.length===1,'pending safe edit');
    await field(page,'Handshake timeout (seconds)').locator('input').fill('27');await field(page,'Handshake timeout (seconds)').locator('input').press('Tab');
    await field(page,'pages.inbounds.port').locator('input').fill('31337');await field(page,'pages.inbounds.port').locator('input').press('Tab');
    await page.locator('.ant-modal:visible .ant-collapse-header').filter({hasText:'Client 1:'}).first().click();
    await field(page,'pages.inbounds.email').locator('input').fill('pending-'+protocol+'@example.invalid');await field(page,'pages.inbounds.email').locator('input').press('Tab');
    deferred.shift()();await ready(page);const merged=await page.evaluate(()=>({data:inModal.inbound.toJson(),error:inModal.inbound.settings.generationError}));
    assert.equal(merged.error,'');assert.equal(merged.data.port,31337);assert.equal(merged.data.settings.handshakeTimeout,27);assert.equal(merged.data.settings.clients[0].email,'pending-'+protocol+'@example.invalid');
    if(protocol==='mieru')assert.equal(merged.data.settings.clients[0].username,uuid);else assert.equal(merged.data.settings.inner.settings.clients[0].email,'pending-shadowtls@example.invalid');
    await close(page);checks.push({protocol,pendingSafeEditsMerged:true});
  }
  await open(page);await choose(page,'mieru');await until(()=>deferred.length===1,'pending credential edit');await page.locator('.ant-modal:visible .ant-collapse-header').filter({hasText:'Client 1:'}).first().click();
  await field(page,'Password').locator('input').fill('deliberately-entered-password');await field(page,'Password').locator('input').press('Tab');deferred.shift()();await ready(page);
  assert.equal(await page.evaluate(()=>inModal.inbound.settings.toJson().clients[0].password),'deliberately-entered-password');assert.match(await page.evaluate(()=>inModal.inbound.settings.generationError),/credentials changed.*kept/i);assert.equal(await page.evaluate(()=>inModal.inbound.settings.generationNotice),'');await close(page);checks.push({pendingCredentialEditPreserved:true});
  // A failed network request is visible, recoverable, and cannot submit an incomplete form.
  mode='network';await open(page);await choose(page,'orbit');await ready(page);assert.ok(await page.evaluate(()=>inModal.inbound.settings.generationError));const failureRequests=requests.length;mode='ok';await page.getByRole('button',{name:'Retry generation',exact:true}).click();await ready(page);assert.equal(await page.evaluate(()=>inModal.inbound.settings.generationError),'');assert.equal(requests.length,failureRequests+1);await close(page);checks.push({networkFailureRetry:true});
  for(const malformed of ['malformed','wrong-protocol','bad-anytls']){
    mode=malformed;await open(page);await choose(page,malformed==='bad-anytls'?'anytls':'orbit');await ready(page);assert.ok(await page.evaluate(()=>inModal.inbound.settings.generationError),malformed+' response rejected');assert.equal(await page.evaluate(()=>inModal.inbound.settings.generationNotice),'');await close(page);checks.push({malformedResponse:malformed,rejected:true});
  }
  for(const request of requests){assert.equal(request.method,'POST');assert.equal(request.headers['content-type'],'application/json');assert.equal(request.headers['x-requested-with'],'XMLHttpRequest');}
  assert.deepEqual(errors,[],'no browser page exceptions');assert.deepEqual(consoleErrors.filter(message=>!message.includes('net::ERR_EMPTY_RESPONSE')),[],'no unexpected browser console errors');
  console.log(JSON.stringify({passed:true,checks,profileRequests:requests.length,submissions:submissions.length},null,2));
 }finally{for(const release of deferred)release();if(browser)await browser.close();server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
