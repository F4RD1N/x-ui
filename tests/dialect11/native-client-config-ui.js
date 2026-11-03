'use strict';
// Actual Go-rendered page, local Vue/Ant/application scripts and UI events.
// Only HTTP/WebSocket peers and browser clipboard primitives are synthetic.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http');
const {execFileSync} = require('node:child_process');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd11-native-client-config-ui-'));
const helper = path.join(temp, 'render.go');
fs.writeFileSync(helper, `package main
import("html/template";"os";"path/filepath";"strings";"github.com/nicksnyder/go-i18n/v2/i18n";"github.com/pelletier/go-toml/v2";"golang.org/x/text/language")
func main(){root:=os.Args[1];lang:=os.Args[2];bundle:=i18n.NewBundle(language.MustParse("en-US"));bundle.RegisterUnmarshalFunc("toml",toml.Unmarshal);for _,name:=range []string{"translate.en_US.toml","translate.fa_IR.toml"}{if _,err:=bundle.LoadMessageFile(filepath.Join(root,"web/translation",name));err!=nil{panic(err)}};localizer:=i18n.NewLocalizer(bundle,lang);t:=template.New("").Funcs(template.FuncMap{"i18n":func(key string,args ...string)string{data:=map[string]any{};for _,arg:=range args{pair:=strings.SplitN(arg,"==",2);if len(pair)==2{data[pair[0]]=pair[1]}};value,err:=localizer.Localize(&i18n.LocalizeConfig{MessageID:key,TemplateData:data});if err!=nil{return key};return value}});err:=filepath.WalkDir(filepath.Join(root,"web/html"),func(p string,d os.DirEntry,e error)error{if e!=nil{return e};if d.IsDir()||!strings.HasSuffix(p,".html"){return nil};b,e:=os.ReadFile(p);if e!=nil{return e};_,e=t.New(filepath.Base(p)).Parse(string(b));return e});if err!=nil{panic(err)};err=t.ExecuteTemplate(os.Stdout,"inbounds.html",map[string]any{"base_path":"/fixture/","cur_ver":"test","host":"127.0.0.1","title":"menu.inbounds","request_uri":"/fixture/panel/inbounds","lang":lang});if err!=nil{panic(err)}}
`);
const rendered = Object.fromEntries(['en-US','fa-IR'].map(locale=>[locale,execFileSync('go', ['run', helper, root, locale], {cwd:root,encoding:'utf8',maxBuffer:8<<20,env:{...process.env,GOMAXPROCS:'2'}})]));
const uuid = '00112233-4455-4677-8899-aabbccddeeff';
const protocols = ['orbit','dnstt','openvpn','anytls','shadowtls','mieru'];
function inbound(id, protocol, enabled = true) {
  const names = protocol === 'anytls' && enabled ? ['first','selected','disabled','depleted','expired'] : ['first','selected'];
  const clients = names.map((name,index) => ({
    email:`${protocol}-${id}-${name}@example.invalid`,enable:name!=='disabled',subId:'',
    id:uuid,password:`synthetic-${id}-${index}`,username:`user-${id}-${index}`,key:'vck1_'+'A'.repeat(86),commonName:`client-${id}-${index}`,
    level:0,totalGB:name==='depleted'?100:0,expiryTime:name==='expired'?1:0,limitIp:0,reset:0,
  }));
  const settings = {clients,handshakeTimeout:10,futureOption:{preserved:true}};
  if(protocol==='vless')settings.decryption='none';
  const clientStats = clients.map((client,index)=>({id:id*10+index,inboundId:id,email:client.email,enable:client.enable,up:client.email.includes('-depleted@')?100:0,down:0,total:client.totalGB,expiryTime:client.expiryTime,allTime:0}));
  return {id,userId:1,up:0,down:0,allTime:0,total:0,remark:`Row ${id} ${protocol}`,enable:enabled,expiryTime:0,listen:'127.0.0.1',port:29000+id,protocol,settings:JSON.stringify(settings),streamSettings:JSON.stringify({network:'tcp',security:'none'}),tag:`inbound-${id}`,sniffing:'{}',clientStats,trafficReset:'never',lastTrafficResetTime:0};
}
const dataset = protocols.map((protocol,index)=>inbound(index+1,protocol));
const legacy = inbound(7,'vless'), disabledInbound = inbound(8,'anytls',false);
dataset.push(legacy,disabledInbound);
function clientConfig(row,email) {
  return {
    remarks:`Selected ${row.protocol} ${email}`,
    log:{loglevel:'warning'},
    inbounds:[{tag:'socks',listen:'127.0.0.1',port:10808,protocol:'socks',settings:{auth:'noauth',udp:true}}],
    outbounds:[{tag:'proxy',protocol:row.protocol==='dnstt'?'dns':row.protocol,settings:{server:{address:'192.0.2.47',port:443},fixtureSelectedEmail:email}},{tag:'direct',protocol:'freedom',settings:{}},{tag:'block',protocol:'blackhole',settings:{}}],
    routing:{domainStrategy:'AsIs',rules:[]},
  };
}
const requests=[],deferred=[],checks=[];
let mode='ok',browser;
function json(res,body,status=200){if(res.destroyed)return;res.statusCode=status;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(body));}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://127.0.0.1');
  if(url.pathname==='/fixture/panel/inbounds'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(rendered[url.searchParams.get('locale')||'en-US']);return;}
  if(url.pathname.startsWith('/fixture/assets/')){
    const file=path.resolve(root,'web',url.pathname.slice('/fixture/'.length));
    if(!file.startsWith(path.join(root,'web/assets')+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
    res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');fs.createReadStream(file).pipe(res);return;
  }
  let body='';for await(const chunk of req)body+=chunk;
  const match=url.pathname.match(/^\/fixture\/panel\/api\/inbounds\/(\d+)\/clientConfig$/);
  if(match){
    let input;try{input=JSON.parse(body);}catch(_){json(res,{success:false,msg:'JSON request required'},400);return;}
    const id=Number(match[1]),row=dataset.find(row=>row.id===id);
    requests.push({id,input,method:req.method,headers:req.headers,path:url.pathname});
    if(!row){json(res,{success:false,msg:'Unknown inbound'},404);return;}
    const config=clientConfig(row,input.email),filename=`client-${row.protocol}-${id}.json`;
    const reply=()=>json(res,{success:true,msg:'',obj:{config,filename}});
    if(mode==='hold'){deferred.push(reply);return;}
    if(mode==='http'){json(res,{success:false,msg:'Fixture HTTP failure'},500);return;}
    if(mode==='api'){json(res,{success:false,msg:'Fixture API rejection',obj:null});return;}
    if(mode==='array'){json(res,{success:true,obj:{config:[],filename}});return;}
    if(mode==='incomplete'){json(res,{success:true,obj:{config:{outbounds:config.outbounds},filename}});return;}
    if(mode==='null-entry'){config.inbounds=[null];json(res,{success:true,obj:{config,filename}});return;}
    if(mode==='protocol-type'){config.outbounds[0].protocol=42;json(res,{success:true,obj:{config,filename}});return;}
    if(mode==='bad-json'){res.setHeader('Content-Type','application/json');res.end('{broken');return;}
    reply();return;
  }
  let obj;
  if(url.pathname.endsWith('/panel/api/inbounds/list'))obj=dataset;
  else if(url.pathname.endsWith('/panel/api/inbounds/onlines'))obj=[];
  else if(url.pathname.endsWith('/panel/api/inbounds/lastOnline'))obj={};
  else if(url.pathname.endsWith('/panel/setting/defaultSettings'))obj={expireDiff:0,trafficDiff:0,defaultCert:'',defaultKey:'',tgBotEnable:false,subEnable:false,subTitle:'Fixture',subURI:'',subJsonURI:'',subJsonEnable:false,pageSize:25,remarkModel:'-ieo',datepicker:'gregorian',ipLimitEnable:false};
  else if(url.pathname.endsWith('/panel/api/server/status'))obj={xray:{state:'running'}};
  else if(url.pathname==='/favicon.ico'){res.writeHead(204);res.end();return;}
  else{res.writeHead(404);res.end('Unexpected fixture request '+url.pathname);return;}
  json(res,{success:true,obj});
});
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(predicate,label){for(let i=0;i<100;i++){if(predicate())return;await sleep(50);}throw new Error('Timed out: '+label);}
function topRow(page,row){return page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').filter({hasText:row.remark});}
async function expandedRow(page,row){
  const tr=topRow(page,row),icon=tr.locator('.ant-table-row-expand-icon');
  if(!await icon.evaluate(node=>node.classList.contains('ant-table-row-expanded')))await icon.click();
  const expanded=tr.locator('xpath=following-sibling::tr[1]');await expanded.locator('.client-email').first().waitFor({state:'visible'});return expanded;
}
async function clientRow(page,row,which='selected'){
  const email=JSON.parse(row.settings).clients.find(client=>client.email.includes('-'+which+'@')).email;
  const expanded=await expandedRow(page,row);
  return {email,element:expanded.locator('tr.ant-table-row').filter({has:page.locator('.client-email').getByText(email,{exact:true})})};
}
async function clipboard(page,mode='success',value='unchanged sentinel',exec='fail'){
  await page.evaluate(({mode,value,exec})=>{window.clipboardFixture.mode=mode;window.clipboardFixture.exec=exec;window.clipboardFixture.value=value;},{mode,value,exec});
}
async function copied(page,expected){await page.waitForFunction(value=>window.clipboardFixture.value!==value,'unchanged sentinel');assert.deepEqual(JSON.parse(await page.evaluate(()=>window.clipboardFixture.value)),expected);}
function visibleMenu(page){return page.locator('.ant-dropdown:visible .ant-dropdown-menu').last();}
async function nativeAction(page,row,which='selected',mobile=false){
  const target=await clientRow(page,row,which);
  if(mobile){await target.element.locator('i.anticon-ellipsis').click();await visibleMenu(page).waitFor({state:'visible'});return {...target,control:visibleMenu(page).locator('.native-client-config-copy-menu')};}
  return {...target,control:target.element.locator('.native-client-config-copy')};
}
async function closeMenu(page){await page.locator('#app').click({position:{x:20,y:20}});await page.waitForTimeout(220);}
async function closeFallback(page){await page.locator('.ant-modal:visible .ant-modal-close').click();await page.waitForTimeout(220);}
(async()=>{
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROME||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true});const errors=[],consoleErrors=[];
  page.on('pageerror',error=>errors.push(error.message));page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text());});
  await page.addInitScript(()=>{
    localStorage.setItem('isRefreshEnabled','false');window.WebSocket=class{static OPEN=1;static CLOSED=3;constructor(){this.readyState=1;setTimeout(()=>this.onopen?.({}),10);}send(){}close(){this.readyState=3;}};
    window.clipboardFixture={mode:'success',exec:'fail',value:'unchanged sentinel',attempts:[],writes:[]};
    Object.defineProperty(navigator,'clipboard',{configurable:true,get(){return window.clipboardFixture.mode==='missing'?undefined:{writeText:async text=>{const state=window.clipboardFixture;state.attempts.push(text);if(state.mode!=='success')throw new DOMException('Fixture clipboard denied','NotAllowedError');state.value=text;state.writes.push({kind:'clipboard',text});}};}});
    document.execCommand=command=>{const state=window.clipboardFixture;if(command!=='copy'||state.exec!=='success')return false;const active=document.activeElement;const text=active&&typeof active.value==='string'?active.value.slice(active.selectionStart??0,active.selectionEnd??active.value.length):String(window.getSelection());state.value=text;state.writes.push({kind:'execCommand',text});return true;};
  });
  await page.goto('http://127.0.0.1:'+server.address().port+'/fixture/panel/inbounds');await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
  assert.equal(await page.evaluate(()=>app.subSettings.enable||app.subSettings.subJsonEnable),false);
  for(const layout of ['desktop','mobile']){
    const mobile=layout==='mobile';await page.setViewportSize(mobile?{width:390,height:844}:{width:1440,height:1100});await page.waitForFunction(mobile=>app.isMobile===mobile,mobile);
    for(const row of dataset.slice(0,6)){
      await clipboard(page);const before=requests.length;const action=await nativeAction(page,row,'selected',mobile);await action.control.click();await until(()=>requests.length===before+1,row.protocol+' copy request');
      assert.deepEqual(requests.at(-1).input,{email:action.email});assert.equal(requests.at(-1).id,row.id);await copied(page,clientConfig(row,action.email));
      if(!mobile)assert.equal(await action.control.getAttribute('aria-label'),'Copy full JSON config');
      assert.equal(await page.locator('.ant-modal:visible').count(),0,'successful copy needs no dialog');checks.push({layout,protocol:row.protocol,selectedClient:true,subscriptionsNotRequired:true,copied:true});if(mobile)await closeMenu(page);
    }
    const old=await clientRow(page,legacy);assert.equal(await old.element.locator('.native-client-config-copy').count(),0,'legacy desktop action unchanged');
    if(mobile){await old.element.locator('i.anticon-ellipsis').click();assert.equal(await visibleMenu(page).locator('.native-client-config-copy-menu').count(),0);assert.equal(await visibleMenu(page).locator('i.anticon-qrcode').count(),1);await closeMenu(page);}else assert.equal(await old.element.locator('i.anticon-qrcode').count(),1);
    const anytls=dataset.find(row=>row.protocol==='anytls');
    for(const [row,which] of [[anytls,'disabled'],[anytls,'depleted'],[anytls,'expired'],[disabledInbound,'selected']]){
      await clipboard(page);const before=requests.length;const action=await nativeAction(page,row,which,mobile);
      if(await action.control.count())await action.control.evaluate(node=>node.click());await page.waitForTimeout(80);assert.equal(requests.length,before,layout+' '+which+' no request');assert.equal(await page.evaluate(()=>window.clipboardFixture.value),'unchanged sentinel');if(mobile)await closeMenu(page);
    }
    checks.push({layout,legacyUnchanged:true,ineligibleClientsBlocked:true});
  }
  await page.setViewportSize({width:1440,height:1100});await page.waitForFunction(()=>!app.isMobile);
  const row=dataset[0];
  // Two rapid clicks and another client while pending must produce one request/write.
  await clipboard(page);mode='hold';const duplicate=await nativeAction(page,row);const beforeDuplicate=requests.length;
  await duplicate.control.evaluate(node=>{node.click();node.click();});await until(()=>deferred.length===1,'duplicate request');const other=await nativeAction(page,dataset[1]);await other.control.evaluate(node=>node.click());await page.waitForTimeout(80);assert.equal(requests.length,beforeDuplicate+1,'global busy guard');deferred.shift()();await copied(page,clientConfig(row,duplicate.email));mode='ok';checks.push({duplicateAndConcurrentClicksSingleRequest:true});
  // Refreshes during a pending export cannot copy a stale/removed client's configuration.
  for(const changed of ['settings','streamSettings','removed']){
    await clipboard(page);mode='hold';const action=await nativeAction(page,row);await action.control.click();await until(()=>deferred.length===1,changed+' pending request');
    const original=changed==='removed'?null:row[changed];
    if(changed==='removed')dataset.splice(dataset.indexOf(row),1);else row[changed]=JSON.stringify({...JSON.parse(original),fixtureChanged:true});
    await page.evaluate(()=>app.getDBInbounds());deferred.shift()();await page.waitForFunction(()=>app.nativeClientConfigBusy==='');
    assert.equal(await page.evaluate(()=>window.clipboardFixture.value),'unchanged sentinel',changed+' stale reply preserves clipboard');assert.equal(await page.locator('.ant-modal:visible').count(),0);
    if(changed==='removed')dataset.unshift(row);else row[changed]=original;await page.evaluate(()=>app.getDBInbounds());mode='ok';checks.push({staleResponse:changed,clipboardPreserved:true});
  }
  // Failed requests and malformed complete-config payloads never change existing clipboard content.
  for(const failure of ['http','api','array','incomplete','null-entry','protocol-type','bad-json']){
    await clipboard(page);mode=failure;const action=await nativeAction(page,row);const before=requests.length;await action.control.click();await until(()=>requests.length===before+1,failure+' request');await page.waitForTimeout(160);
    assert.equal(await page.evaluate(()=>window.clipboardFixture.value),'unchanged sentinel',failure+' preserves clipboard');assert.equal(await page.locator('.ant-modal:visible').count(),0,failure+' no misleading config dialog');
    // The next real click must work, proving busy was cleared on the error path.
    mode='ok';await action.control.click();await until(()=>requests.length===before+2,failure+' recovery');await copied(page,clientConfig(row,action.email));checks.push({failure,clipboardPreserved:true,nextClickRecovers:true});
  }
  // Clipboard permission rejection can succeed via the actual helper's execCommand fallback.
  for(const primitive of ['denied','missing']){
    await clipboard(page,primitive,'unchanged sentinel','success');const action=await nativeAction(page,row);await action.control.click();await copied(page,clientConfig(row,action.email));assert.equal(await page.locator('.ant-modal:visible').count(),0);assert.equal(await page.evaluate(()=>window.clipboardFixture.writes.at(-1).kind),'execCommand');checks.push({clipboardPrimitive:primitive,execFallback:true});
  }
  // If both primitives fail, the complete JSON remains visible/read-only and downloadable.
  await clipboard(page,'denied');const action=await nativeAction(page,row),beforeFallback=requests.length;await action.control.click();const modal=page.locator('.ant-modal:visible');await modal.locator('textarea').waitFor({state:'visible'});
  const textarea=modal.locator('textarea');assert.equal(await textarea.getAttribute('readonly')!==null,true);assert.deepEqual(JSON.parse(await textarea.inputValue()),clientConfig(row,action.email));assert.equal(await page.evaluate(()=>window.clipboardFixture.value),'unchanged sentinel');
  await modal.locator('.native-client-json-copy').click();await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>window.clipboardFixture.value),'unchanged sentinel');assert.equal(requests.length,beforeFallback+1,'manual Copy reuses fetched payload');
  const downloadPromise=page.waitForEvent('download');await modal.locator('.native-client-json-download').click();const download=await downloadPromise;assert.equal(download.suggestedFilename(),`client-${row.protocol}-${row.id}.json`);const downloadFile=path.join(temp,'download.json');await download.saveAs(downloadFile);assert.deepEqual(JSON.parse(fs.readFileSync(downloadFile,'utf8')),clientConfig(row,action.email));
  await clipboard(page,'success');await modal.locator('.native-client-json-copy').click();await copied(page,clientConfig(row,action.email));assert.equal(requests.length,beforeFallback+1);await page.waitForFunction(()=>!nativeClientJsonModal.visible);assert.equal(await page.evaluate(()=>nativeClientJsonModal.content+nativeClientJsonModal.filename),'');checks.push({clipboardFailureReadonlyModal:true,manualCopyActualEvent:true,downloadActualEvent:true,noRefetch:true,clearOnClose:true});
  // Real Farsi translations pass through Go's HTML/attribute/script contextual escaping.
  await page.setViewportSize({width:1440,height:1100});await page.goto('http://127.0.0.1:'+server.address().port+'/fixture/panel/inbounds?locale=fa-IR');await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
  for(const mobile of [false,true]){
    await page.setViewportSize(mobile?{width:390,height:844}:{width:1440,height:1100});await page.waitForFunction(value=>app.isMobile===value,mobile);await clipboard(page);
    const action=await nativeAction(page,row,'selected',mobile);assert.equal(mobile?(await action.control.innerText()).trim():await action.control.getAttribute('aria-label'),'کپی کانفیگ کامل JSON');await action.control.click();await copied(page,clientConfig(row,action.email));if(mobile)await closeMenu(page);checks.push({locale:'fa-IR',layout:mobile?'mobile':'desktop',translatedAction:true,copied:true});
  }
  await clipboard(page,'denied');const faAction=await nativeAction(page,row,'selected',true);await faAction.control.click();const faModal=page.locator('.ant-modal:visible');await faModal.locator('.native-client-json-content').waitFor({state:'visible'});
  assert.equal((await faModal.locator('.ant-modal-title').innerText()).trim(),'کپی کانفیگ کامل JSON');assert.equal(await faModal.locator('.native-client-json-content').getAttribute('readonly')!==null,true);assert.deepEqual(JSON.parse(await faModal.locator('.native-client-json-content').inputValue()),clientConfig(row,faAction.email));
  await clipboard(page,'success');await faModal.locator('.native-client-json-copy').click();await copied(page,clientConfig(row,faAction.email));await page.waitForFunction(()=>!nativeClientJsonModal.visible);
  await clipboard(page,'denied');const closeAction=await nativeAction(page,row,'selected',true);await closeAction.control.click();await page.locator('.ant-modal:visible .native-client-json-content').waitFor({state:'visible'});await closeFallback(page);assert.equal(await page.evaluate(()=>nativeClientJsonModal.content+nativeClientJsonModal.filename),'');checks.push({locale:'fa-IR',translatedFallback:true,readonly:true,manualCopy:true,clearOnManualClose:true});
  for(const request of requests){assert.equal(request.method,'POST');assert.equal(request.headers['content-type'],'application/json');assert.equal(request.headers['x-requested-with'],'XMLHttpRequest');assert.deepEqual(Object.keys(request.input),['email']);}
  assert.deepEqual(errors,[],'no browser page exceptions');assert.deepEqual(consoleErrors.filter(message=>!message.includes('the server responded with a status of 500')),[],'no unexpected browser console errors');
  console.log(JSON.stringify({passed:true,checks,requests:requests.length},null,2));
 }finally{for(const release of deferred)release();if(browser)await browser.close();server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
