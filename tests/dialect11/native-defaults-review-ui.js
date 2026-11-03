'use strict';
// Independent full-page review. Real Go templates, Vue, Ant and form/controller
// methods are used. HTTP persistence is a fixture; credential responses execute
// the production service helpers. Authentication/traffic are tested separately.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {execFileSync}=require('node:child_process');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'../..');
const sourceFiles=['web/assets/js/model/inbound.js','web/assets/js/model/outbound.js','web/assets/js/model/native-inbound.js','web/assets/js/model/native-creation.js','web/assets/js/model/native-modes.js','web/assets/js/model/dbinbound.js','web/html/inbounds.html','web/html/modals/inbound_modal.html','web/html/modals/client_modal.html','web/html/form/protocol/native.html','web/html/form/client.html','web/service/native_profile.go','web/service/native_credentials.go','sub/native_export.go'];
const sourceHashes=()=>Object.fromEntries(sourceFiles.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex')]));
const sourceBefore=sourceHashes();
const work=process.env.REVIEW_OUTPUT||fs.mkdtempSync(path.join(os.tmpdir(),'native-defaults-review-'));
fs.mkdirSync(work,{recursive:true,mode:0o700});
const helper=path.join(work,'render.go');
fs.writeFileSync(helper,`package main
import("html/template";"os";"path/filepath";"strings")
func main(){root:=os.Args[1];t:=template.New("").Funcs(template.FuncMap{"i18n":func(k string,args ...string)string{return k}});err:=filepath.WalkDir(filepath.Join(root,"web/html"),func(p string,d os.DirEntry,e error)error{if e!=nil{return e};if d.IsDir()||!strings.HasSuffix(p,".html"){return nil};b,e:=os.ReadFile(p);if e!=nil{return e};_,e=t.New(filepath.Base(p)).Parse(string(b));return e});if err!=nil{panic(err)};if e:=t.ExecuteTemplate(os.Stdout,"inbounds.html",map[string]any{"base_path":"/review/","cur_ver":"review","host":"127.0.0.1","title":"menu.inbounds","request_uri":"/review/panel/inbounds","lang":"en-US"});e!=nil{panic(e)}}`);
const rendered=execFileSync('go',['run',helper,root],{encoding:'utf8',maxBuffer:8<<20,env:{...process.env,GOMAXPROCS:'2'}});
const credentialHelper=process.env.NATIVE_CREDENTIAL_HELPER||path.join(work,'credentials');
if(!process.env.NATIVE_CREDENTIAL_HELPER)execFileSync('go',['build','-p','1','-o',credentialHelper,path.join(__dirname,'native-credentials-review-helper.go')],{cwd:root,env:{...process.env,GOMAXPROCS:'2'}});
const clone=o=>JSON.parse(JSON.stringify(o));
const protocols=['anytls','mieru','dnstt','orbit','openvpn','shadowtls'];
const calls=[],saves=[],errors=[],results=[];
let rows=[],mode='success',delay=0,browser,page,sequence=1,caseName='',nextPort=35000;
function generate(request){return JSON.parse(execFileSync(credentialHelper,[],{input:JSON.stringify(request),encoding:'utf8',maxBuffer:2<<20}));}
function rowFor(protocol,profile,id=sequence++){
 const settings=profile.settings;
 return {id,userId:1,up:0,down:0,allTime:0,total:0,remark:'Review '+protocol,enable:true,expiryTime:0,listen:'127.0.0.1',port:28000+id,protocol,settings:JSON.stringify(settings),streamSettings:JSON.stringify(profile.streamSettings||{}),sniffing:'{}',tag:'inbound-'+id,trafficReset:'never',lastTrafficResetTime:0,clientStats:settings.clients.map((c,i)=>({id:i+1,inboundId:id,email:c.email,enable:true,up:0,down:0,total:0,expiryTime:0,allTime:0}))};
}
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://127.0.0.1');
 if(url.pathname==='/review/panel/inbounds'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(rendered);return;}
 if(url.pathname.startsWith('/review/assets/')){
  const file=path.resolve(root,'web',url.pathname.slice('/review/'.length));
  if(!file.startsWith(path.join(root,'web/assets')+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'application/octet-stream');fs.createReadStream(file).pipe(res);return;
 }
 const reply=obj=>{if(!res.destroyed){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(obj));}};
 if(url.pathname.endsWith('/native/credentials')){
  let body='';for await(const b of req)body+=b;
  let request;try{request=JSON.parse(body);}catch{reply({success:false,msg:'invalid request'});return;}
  calls.push({request,contentType:req.headers['content-type'],path:url.pathname});
  let response;
  try{response=mode==='failure'?{success:false,msg:'Synthetic temporary generation failure'}:mode==='malformed'?{success:true,obj:{settings:{clients:[]}}}:generate(request);}catch(error){response={success:false,msg:error.message};}
  if(mode==='wrongProtocol'&&response.success)response.obj.protocol='wrong-protocol';
  if(delay)setTimeout(()=>reply(response),delay);else reply(response);
  return;
 }
 if(url.pathname.endsWith('/panel/api/inbounds/add')||url.pathname.endsWith('/panel/api/inbounds/addClient')){
  let body='';for await(const b of req)body+=b;
  const data=Object.fromEntries(new URLSearchParams(body));const capture={case:caseName,path:url.pathname,data,rawBody:body};saves.push(capture);
  if(url.pathname.endsWith('/add')){
   const p={settings:JSON.parse(data.settings),streamSettings:JSON.parse(data.streamSettings||'{}')};
   const row=rowFor(data.protocol,p);row.port=Number(data.port);row.remark=data.remark||row.remark;rows.push(row);capture.responseId=row.id;
  }
  reply({success:true,obj:null});return;
 }
 let obj;
 if(url.pathname.endsWith('/panel/api/inbounds/list'))obj=rows;
 else if(url.pathname.endsWith('/panel/api/inbounds/onlines'))obj=[];
 else if(url.pathname.endsWith('/panel/api/inbounds/lastOnline'))obj={};
 else if(url.pathname.endsWith('/panel/setting/defaultSettings'))obj={expireDiff:0,trafficDiff:0,defaultCert:'',defaultKey:'',tgBotEnable:false,subEnable:true,subJsonEnable:true,subTitle:'Review',subURI:'https://example.invalid/sub/',subJsonURI:'https://example.invalid/json/',pageSize:25,remarkModel:'-ieo',datepicker:'gregorian',ipLimitEnable:false};
 else if(url.pathname.endsWith('/panel/api/server/status'))obj={xray:{state:'running'}};
 else if(url.pathname==='/favicon.ico'){res.writeHead(204);res.end();return;}
 else{res.writeHead(404);res.end();return;}
 reply({success:true,obj});
});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function load(initialRows=[]){
 rows=clone(initialRows);sequence=1;mode='success';delay=0;
 await page.goto('http://127.0.0.1:'+server.address().port+'/review/panel/inbounds');
 await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning);
}
// These are explicitly supplied, isolated test deployment values. They are not
// production defaults, and the no-input tests below verify the form stays blank.
async function openNew(protocol, supply=true){
 await page.getByRole('button',{name:/pages\.inbounds\.addInbound$/}).click();
 await page.evaluate(({protocol,port})=>{inModal.inbound.protocol=protocol;inModal.inbound.port=port;},{protocol,port:nextPort++});
 // Let the protocol-change watcher see the untouched form before entering data,
 // just as separate user interactions do.
 await page.waitForTimeout(20);
 if(!supply)return;
 await page.evaluate(protocol=>{
  const port=inModal.inbound.port;const settings=inModal.inbound.settings;
  const set=(path,value)=>{const field=settings.fields.find(f=>f.path===path);if(!field)throw new Error('Missing deployment field '+path);settings.setField(field,value);};
  if(protocol==='anytls')set('clientExport.serverName','127.0.0.1');
  if(protocol==='orbit')set('clientExport.address','127.0.0.1');
  if(protocol==='dnstt'){set('domain','tunnel.review.test');set('clientExport.resolvers',JSON.stringify([{transport:'udp',address:'127.0.0.1:'+port}]));}
  if(protocol==='shadowtls')set('handshake.address','127.0.0.1');
 },protocol);
 if(supply&&['anytls','orbit'].includes(protocol))await page.getByRole('button',{name:'Generate credentials',exact:true}).click();
}
async function settled(){await page.waitForFunction(()=>inModal.inbound.isNative&&!inModal.inbound.settings.generating&&!inModal.inbound.settings.modeDefaultsPending&&(!inModal.inbound.settings.needsProfile||inModal.inbound.settings.generationError),{},{timeout:10000});await page.waitForTimeout(30);}
async function state(){return page.evaluate(()=>({json:inModal.inbound.toJson(),errors:inModal.inbound.settings.validationErrors,generating:inModal.inbound.settings.generating,error:inModal.inbound.settings.generationError,needs:inModal.inbound.settings.needsProfile}));}
function validateOrbitSettings(input,label){
 fs.writeFileSync(path.join(work,label+'-panel-settings.json'),JSON.stringify(input));
 const settings=clone(input);delete settings.clientExport;settings.clients=settings.clients.map(c=>({email:c.email,key:c.key,level:c.level}));
 const config=path.join(work,label+'-core.json');fs.writeFileSync(config,JSON.stringify({inbounds:[{listen:'127.0.0.1',port:29091,protocol:'orbit',settings}],outbounds:[{protocol:'freedom'}]}));
 if(process.env.REVIEW_CORE){try{const output=execFileSync(process.env.REVIEW_CORE,['run','-test','-config',config],{encoding:'utf8',stdio:['ignore','pipe','pipe']});fs.writeFileSync(path.join(work,label+'-core.log'),output);}catch(error){const output=String(error.stdout||'')+String(error.stderr||'');fs.writeFileSync(path.join(work,label+'-core.log'),output);throw new Error(output.slice(-1000));}}
}
async function changeNativeField(field,value){await page.evaluate(({field,value})=>{const settings=inModal.inbound.settings;const descriptor=settings.fields.find(f=>f.path===field);if(!descriptor)throw new Error('Missing native field '+field);settings.setField(descriptor,value);},{field,value});await settled();}
function complete(protocol,settings,client= settings.clients[0]){
 assert.ok(client.email&&client.subId,protocol+' panel identity');
 if(protocol==='openvpn'){for(const k of ['ca','cert','key'])assert.match(settings.certificates[k],/-----BEGIN /);assert.match(client.certificate,/BEGIN CERTIFICATE/);assert.match(client.privateKey,/BEGIN .*PRIVATE KEY/);assert.ok(client.commonName);if(settings.certificates.tlsCryptV2)assert.match(client.tlsCryptV2,/BEGIN OpenVPN tls-crypt-v2 client key/);}
 if(protocol==='orbit')assert.match(client.key,/^vck1_[A-Za-z0-9_-]{86}$/);
 if(protocol==='dnstt'){assert.match(settings.privateKey,/^[a-f0-9]{64}$/i);assert.ok(settings.domain);assert.ok(client.id||client.username&&client.password);}
 if(protocol==='anytls')assert.ok(client.password);
 if(protocol==='mieru')assert.ok(client.username&&client.password);
 if(protocol==='shadowtls'){assert.ok(client.password);assert.ok(settings.handshake.address);const inner=settings.inner.settings;assert.ok((inner.clients||[]).some(c=>c.email===client.email&&c.password||c.email===client.email&&c.id)||(inner.accounts||[]).some(c=>c.user===(client.innerUsername||client.email)), 'inner binding for '+client.email);}
}
async function check(name,fn){if(process.env.REVIEW_ONLY&&!name.includes(process.env.REVIEW_ONLY))return;caseName=name;const before=errors.length;try{await fn();assert.deepEqual(errors.slice(before),[],name+' Vue/page errors');results.push({name,ok:true});console.log('PASS '+name);}catch(error){results.push({name,ok:false,error:error.message});console.log('FAIL '+name+': '+error.message);await page.screenshot({path:path.join(work,name.replace(/[^a-z0-9_-]/ig,'_')+'.png'),fullPage:true}).catch(()=>{});}}
(async()=>{
 try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROME||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
 page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 await page.addInitScript(()=>{localStorage.setItem('isRefreshEnabled','false');window.WebSocket=class{static OPEN=1;static CLOSED=3;constructor(){this.readyState=1;setTimeout(()=>this.onopen?.({}),10);}send(){}close(){this.readyState=3;}};});
 await check('explicit-identity-normalization-and-trust',async()=>{
  for(const [protocol,input,expected,label] of [['anytls',' 127.0.0.1 ','127.0.0.1','ipv4'],['anytls',' [::1] ','::1','ipv6'],['anytls',' VPN.REVIEW.TEST. ','vpn.review.test','dns'],['orbit',' [::1] ','::1','orbit-ipv6']]){
   caseName='explicit-identity-normalization-and-trust-'+label;
   await load();await openNew(protocol,false);const fieldPath=protocol==='anytls'?'clientExport.serverName':'clientExport.address';
   await page.evaluate(({fieldPath,input})=>{const settings=inModal.inbound.settings;settings.setField(settings.fields.find(f=>f.path===fieldPath),input);},{fieldPath,input});
   await page.getByRole('button',{name:'Generate credentials',exact:true}).click();await settled();const ready=await state();assert.deepEqual(ready.errors,[]);
   assert.equal(protocol==='anytls'?ready.json.settings.clientExport.serverName:ready.json.settings.clientExport.address,expected,'explicit identity must serialize in canonical form');
   if(protocol==='anytls'){assert.match(ready.json.settings.clientExport.ca,/BEGIN CERTIFICATE/);assert.ok(ready.json.streamSettings.tlsSettings.certificates[0].certificate.length);}
   fs.writeFileSync(path.join(work,'identity-'+label+'-inbound.json'),JSON.stringify(ready.json));
   await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible&&app.dbInbounds.length===1);
   assert.equal(JSON.parse(saves.at(-1).data.settings).clientExport[protocol==='anytls'?'serverName':'address'],expected,'actual Create body must contain canonical explicit identity');
  }
 });
 await check('explicit-identity-pending-equivalent-input-preserves-generation',async()=>{
  await load();await openNew('anytls',false);delay=200;const count=calls.length;
  await page.evaluate(()=>{const settings=inModal.inbound.settings;settings.setField(settings.fields.find(f=>f.path==='clientExport.serverName'),' 127.0.0.1 ');});
  await page.getByRole('button',{name:'Generate credentials',exact:true}).click();await page.waitForFunction(()=>inModal.inbound.settings.generating);
  await page.evaluate(()=>{const settings=inModal.inbound.settings;settings.setField(settings.fields.find(f=>f.path==='clientExport.serverName'),'127.0.0.1');});
  await settled();const ready=await state();assert.deepEqual(ready.errors,[]);assert.equal(ready.error,'');assert.equal(calls.length-count,1);assert.equal(ready.json.settings.clientExport.serverName,'127.0.0.1');assert.match(ready.json.settings.clientExport.ca,/BEGIN CERTIFICATE/);
 });
 for(const protocol of protocols){
  await check('manual-prerequisites-blank-'+protocol,async()=>{
   await load();const count=calls.length,beforeSaves=saves.length;await openNew(protocol,false);
   await page.waitForFunction(()=>inModal.inbound.isNative&&!inModal.inbound.settings.generating&&!inModal.inbound.settings.modeDefaultsPending);
   await page.waitForTimeout(60);const blank=await state(),settings=blank.json.settings;
   const optional=value=>value===undefined||value===''||(Array.isArray(value)&&value.length===0);
   for(const value of [settings.domain,settings.host,settings.clientExport?.address,settings.clientExport?.serverName,settings.clientExport?.resolvers,settings.handshake?.address,settings.reality?.dest,settings.reality?.serverNames])assert.ok(optional(value),'real deployment prerequisite was automatically filled');
   if(protocol==='openvpn'){assert.deepEqual(settings.tunnel.dns,[]);assert.equal(settings.tunnel.ipv4,'10.88.0.0/24');complete(protocol,settings);}
   if(protocol==='mieru')complete(protocol,settings);
   if(protocol==='dnstt')assert.match(settings.privateKey,/^[a-f0-9]{64}$/i);
   if(protocol==='shadowtls')assert.ok(settings.clients[0].password&&settings.inner.settings.password);
   assert.equal(calls.length-count,['anytls','orbit'].includes(protocol)?0:1,'only crypto independent of deployment identity may be generated');
   for(const call of calls.slice(count))for(const key of ['serverName','serverAddress','domain','handshakeAddress'])assert.ok(!call.request[key],'request must not infer '+key+' from panel location');
   if(['anytls','orbit','dnstt','shadowtls'].includes(protocol)){
    assert.ok(blank.errors.length,'missing required deployment fields must be invalid');await page.evaluate(()=>inModal.ok());assert.equal(saves.length,beforeSaves,'blank deployment prerequisites cannot save');
    const setInput=async(label,value)=>{const field=page.locator('.ant-modal:visible .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:label})}).locator('input,textarea').first();await field.fill(value);await field.press('Tab');};
    if(protocol==='anytls')await setInput('Client server name','127.0.0.1');
    if(protocol==='orbit')await setInput('Client server address','127.0.0.1');
    if(['anytls','orbit'].includes(protocol)){await page.waitForTimeout(60);assert.equal(calls.length-count,0,'typing identity must not issue or rotate certificates');await page.getByRole('button',{name:'Generate credentials',exact:true}).click();}
    if(protocol==='dnstt'){await setInput('Tunnel name','tunnel.review.test');await setInput('DNS resolvers JSON',JSON.stringify([{transport:'udp',address:'127.0.0.1:'+blank.json.port}]));}
    if(protocol==='shadowtls')await setInput('Handshake TLS target','127.0.0.1');
    await settled();const ready=await state();assert.deepEqual(ready.errors,[]);complete(protocol,ready.json.settings);assert.equal(calls.length-count,1,'manual completion cannot rotate previously generated credentials');
    if(['dnstt','shadowtls'].includes(protocol)){assert.deepEqual(ready.json.settings.clients,settings.clients);assert.equal(ready.json.settings.privateKey,settings.privateKey);assert.deepEqual(ready.json.settings.inner,settings.inner);}
    if(protocol==='anytls')assert.equal(calls.at(-1).request.serverName,'127.0.0.1');
    if(protocol==='orbit')assert.equal(calls.at(-1).request.serverAddress,'127.0.0.1');
    await page.waitForTimeout(60);assert.equal(calls.length-count,1,'valid identity must generate once only');
   }
  });
 }
 await check('outbound-manual-deployment-models-all-six',async()=>{
  const isolated=await browser.newPage();try{
   await isolated.addScriptTag({path:path.join(root,'web/assets/js/util/index.js')});await isolated.addScriptTag({path:path.join(root,'web/assets/js/model/outbound.js')});
   const checks=await isolated.evaluate(()=>{
    let checked=0;const empty=value=>value===undefined||value===''||(Array.isArray(value)&&value.length===0);
    for(const protocol of ['orbit','dnstt','openvpn','anytls','shadowtls','mieru']){
     const model=new Outbound('review',protocol),data=model.settings;
     for(const field of ['address','server.address','domain','host','peer','serverName','tlsSettings.serverName','reality.serverName','resolver','clientProof.keyFile']){if(!empty(data.read(field)))throw new Error(protocol+' invents '+field);checked++;}
     if(!data.validationErrors.length)throw new Error(protocol+' blank outbound is saveable');
     if(protocol==='dnstt'&&data.resolvers.some(item=>item.address))throw new Error('DNSTT resolver must remain blank');
     if(protocol==='openvpn'){data.setProofEnabled(true);data.setProofKeyMode('keyFile');if(data.read('clientProof.keyFile')!=='')throw new Error('Proof path must be blank');}
     if(protocol==='orbit'){data.write('transport','ws');data.write('security','reality');if(data.read('host')||data.read('reality.serverName')||data.read('peer'))throw new Error('Orbit mode change invented prerequisites');}
    }return checked;
   });assert.equal(checks,60);
  }finally{await isolated.close();}
 });
 for(const protocol of protocols){
  await check('new-edit-clone-restore-'+protocol,async()=>{
   await load();const start=calls.length;await openNew(protocol);await settled();const s=await state();assert.deepEqual(s.errors,[]);complete(protocol,s.json.settings);assert.equal(calls.length-start,1,'one automatic profile request');
   const row=rowFor(protocol,{settings:s.json.settings,streamSettings:s.json.streamSettings});
   await page.evaluate(row=>{inModal.close();app.setInbounds([row]);app.openEditInbound(row.id);},row);
   const restored=await state();assert.deepEqual(restored.json.settings,s.json.settings,'edit preserves credentials');await page.waitForTimeout(50);assert.equal(calls.length-start,1,'edit cannot regenerate');
   const copy=await page.evaluate(()=>inModal.inbound.settings.cloneForNewInbound().toJson());
   assert.notEqual(copy.clients[0].email,s.json.settings.clients[0].email);assert.notEqual(copy.clients[0].subId,s.json.settings.clients[0].subId);
   if(protocol==='openvpn')assert.equal(copy.certificates.key,s.json.settings.certificates.key);
   if(protocol==='orbit')assert.equal(copy.clients[0].key,s.json.settings.clients[0].key);
   await load([row]);await page.evaluate(id=>app.openEditInbound(id),row.id);assert.deepEqual((await state()).json.settings,s.json.settings,'persisted/restore reload preserves crypto');assert.equal(calls.length-start,1,'restore cannot regenerate');
  });
 }
 await check('negative-and-safe-profile-merges-all-six',async()=>{
  await load();const profiles=Object.fromEntries(protocols.map(protocol=>[protocol,generate({kind:'inbound-profile',protocol,serverName:'127.0.0.1',serverAddress:'127.0.0.1',domain:'tunnel.review.test',handshakeAddress:'127.0.0.1',email:'generated@example.invalid'}).obj]));
  const proof=await page.evaluate(profiles=>{
   const clone=o=>JSON.parse(JSON.stringify(o));let checks=0;
   for(const [protocol,generated] of Object.entries(profiles)){
    const inbound=new Inbound();inbound.protocol=protocol;const before=inbound.toJson();const original=JSON.stringify({before,generated});
    const reject=(profile,current=before)=>{let rejected=false;try{Inbound.NativeSettings.mergeGeneratedProfile(protocol,profile,before,current);}catch(_){rejected=true;}if(!rejected)throw new Error(protocol+' accepted invalid or stale profile');checks++;};
    reject({...generated,protocol:'wrong-protocol'});reject({protocol,settings:null});reject({protocol,settings:{clients:[]}});reject({protocol,settings:{clients:[null]}});
    const credential=clone(before);credential.settings.privateKey='manual-key';reject(generated,credential);
    const user=clone(before);user.settings.clients[0].password='manual-password';reject(generated,user);
    const current=clone(before);current.port=32123;current.settings.clients[0].email='edited@example.invalid';
    if(protocol==='openvpn')current.settings.limits.handshakeSeconds=23;else current.settings.handshakeTimeout=23;
    const merged=Inbound.NativeSettings.mergeGeneratedProfile(protocol,generated,before,current);
    if(merged.port!==32123||merged.settings.clients[0].email!=='edited@example.invalid'||merged.settings.clients[0].subId!==current.settings.clients[0].subId)throw new Error(protocol+' lost safe form edits');
    if((protocol==='openvpn'?merged.settings.limits.handshakeSeconds:merged.settings.handshakeTimeout)!==23)throw new Error(protocol+' lost timeout edit');
    if(protocol==='shadowtls'&&!merged.settings.inner.settings.clients.some(c=>c.email==='edited@example.invalid'))throw new Error('ShadowTLS merge lost inner email binding');
    if(JSON.stringify({before,generated})!==original)throw new Error(protocol+' merge mutated inputs');checks+=4;
   }
   return checks;
  },profiles);assert.equal(proof,60);
 });
 await check('pending-user-port-and-email-edits',async()=>{
  await load();delay=200;await openNew('openvpn');await page.waitForFunction(()=>inModal.inbound.settings.generating);
  await page.evaluate(()=>{inModal.inbound.port=32456;inModal.inbound.settings.clients[0].email='edited@example.invalid';});
  await settled();const s=await state();assert.equal(s.json.port,32456);assert.equal(s.json.settings.clients[0].email,'edited@example.invalid');assert.deepEqual(s.errors,[],'preserved edits must still receive required material');complete('openvpn',s.json.settings);
 });
 await check('pending-user-crypto-edit-preserved',async()=>{
  await load();delay=200;await openNew('dnstt');await page.waitForFunction(()=>inModal.inbound.settings.generating);
  await page.evaluate(()=>{inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='privateKey'),'ab'.repeat(32));});
  await settled();assert.equal((await state()).json.settings.privateKey,'ab'.repeat(32));
 });
 await check('switch-protocol-cancels-stale-result',async()=>{
  await load();delay=200;await openNew('orbit');await page.waitForFunction(()=>inModal.inbound.settings.generating);
  await page.evaluate(()=>{inModal.inbound.protocol='anytls';});await page.waitForTimeout(20);await page.evaluate(()=>{const settings=inModal.inbound.settings;settings.setField(settings.fields.find(f=>f.path==='clientExport.serverName'),'127.0.0.1');});await page.getByRole('button',{name:'Generate credentials',exact:true}).click();await settled();await sleep(250);const s=await state();assert.equal(s.json.protocol,'anytls');assert.deepEqual(s.errors,[]);assert.ok(s.json.settings.clients[0].password);assert.equal(s.json.settings.clients[0].key,undefined);
 });
 await check('close-reopen-cancels-stale-result',async()=>{
  await load();delay=200;await openNew('orbit');await page.waitForFunction(()=>inModal.inbound.settings.generating);
  await page.evaluate(()=>{inModal.close();app.openAddInbound();inModal.inbound.protocol='mieru';});await settled();await sleep(250);const s=await state();assert.equal(s.json.protocol,'mieru');assert.deepEqual(s.errors,[]);complete('mieru',s.json.settings);
 });
 await check('failure-retry-recovers-without-save-lock',async()=>{
  await load();mode='failure';await openNew('openvpn');await settled();assert.ok((await state()).error);assert.equal((await state()).generating,false);
  mode='success';await page.getByRole('button',{name:'Retry generation',exact:true}).click();await settled();assert.deepEqual((await state()).errors,[]);complete('openvpn',(await state()).json.settings);
 });
 await check('malformed-response-retry-recovers',async()=>{
  await load();mode='malformed';await openNew('anytls');await settled();assert.ok((await state()).error);assert.equal((await state()).generating,false);
  mode='success';await page.getByRole('button',{name:'Generate credentials',exact:true}).click();await settled();assert.deepEqual((await state()).errors,[]);
 });
 await check('telegram-input-validation-does-not-break-render',async()=>{
  await load();await openNew('anytls');await settled();await page.evaluate(()=>{app.tgBotEnable=true;});await page.locator('.ant-collapse-header').filter({hasText:'Client 1:'}).first().click();
  const input=page.locator('.ant-modal:visible .ant-form-item').filter({has:page.locator('.ant-form-item-label',{hasText:'Telegram ChatID'})}).locator('input');const before=saves.length;
  for(const value of ['12.5','9007199254740992']){await input.fill(value);await input.press('Tab');await page.waitForTimeout(30);assert.ok((await state()).errors.some(e=>/Telegram/i.test(e)));await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();assert.equal(saves.length,before,'invalid Telegram value must not submit');}
  await input.fill('123456');await input.press('Tab');await page.waitForTimeout(30);assert.deepEqual((await state()).errors,[]);await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible);assert.equal(JSON.parse(saves.at(-1).data.settings).clients[0].tgId,123456);
 });
 await check('wrong-protocol-response-cannot-replace-form',async()=>{
  await load();mode='wrongProtocol';await openNew('openvpn');await settled();const s=await state();assert.equal(s.json.protocol,'openvpn');assert.ok(s.error);assert.equal(s.generating,false);assert.ok(!s.json.settings.certificates.cert);
  mode='success';await page.getByRole('button',{name:'Retry generation',exact:true}).click();await settled();assert.deepEqual((await state()).errors,[]);
 });
 await check('ordinary-vmess-does-not-generate-native-profile',async()=>{
  await load();const before=calls.length;await page.getByRole('button',{name:/pages\.inbounds\.addInbound$/}).click();await page.evaluate(()=>{inModal.inbound.protocol='vmess';});await page.waitForTimeout(60);assert.equal(calls.length,before);assert.equal(await page.evaluate(()=>inModal.inbound.isNative),false);assert.equal(await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').isDisabled(),false);
 });
 await check('timeout-aborts-retries-and-releases-save',async()=>{
  await load();delay=250;
  await page.evaluate(()=>{window.reviewTimer=window.setTimeout;window.setTimeout=(f,ms,...args)=>window.reviewTimer(f,ms===30000?60:ms,...args);});
  await openNew('openvpn');await settled();const failed=await state();assert.match(failed.error,/timed out/i);assert.equal(failed.generating,false);
  await page.evaluate(()=>{window.setTimeout=window.reviewTimer;});delay=0;await page.getByRole('button',{name:'Retry generation',exact:true}).click();await settled();assert.deepEqual((await state()).errors,[]);complete('openvpn',(await state()).json.settings);
 });
 await check('save-blocked-during-generation-then-recovers',async()=>{
  await load();delay=200;const before=saves.length;await openNew('openvpn');await page.waitForFunction(()=>inModal.inbound.settings.generating);
  assert.equal(await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').isDisabled(),true,'Save disabled while generating');
  await page.evaluate(()=>inModal.ok());assert.equal(saves.length,before,'pending Save cannot submit');
  await settled();assert.deepEqual((await state()).errors,[]);assert.equal(await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').isDisabled(),false);
  await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible&&!inModal.confirmLoading);assert.equal(saves.length,before+1);complete('openvpn',JSON.parse(saves.at(-1).data.settings));
 });
 for(const protocol of protocols){
  await check('inbound-add-client-'+protocol,async()=>{
   await load();await openNew(protocol);await settled();const before=await state();assert.deepEqual(before.errors,[]);await page.getByRole('button',{name:/Add client$/}).click();
   await page.waitForFunction(()=>!inModal.inbound.settings.generating);const s=await state();assert.equal(s.json.settings.clients.length,2);assert.deepEqual(s.errors,[]);complete(protocol,s.json.settings,s.json.settings.clients[1]);assert.notEqual(JSON.stringify(s.json.settings.clients[0]),JSON.stringify(s.json.settings.clients[1]));
   if(protocol==='openvpn')assert.notEqual(s.json.settings.clients[0].privateKey,s.json.settings.clients[1].privateKey);
  });
  await check('standalone-add-client-'+protocol,async()=>{
   await load();await openNew(protocol);await settled();const s=await state();assert.deepEqual(s.errors,[]);
   await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible&&app.dbInbounds.length===1);
   await page.evaluate(()=>app.openAddClient(app.dbInbounds[0].id));
   await page.waitForFunction(()=>clientModal.visible&&!clientModal.inbound.settings.generating);
   const added=await page.evaluate(()=>({settings:clientModal.inbound.settings.toJson(),client:clientModalApp.client.toJson(),errors:clientModalApp.client.validationErrors}));
   assert.deepEqual(added.errors,[]);complete(protocol,added.settings,added.client);
   const beforeSave=saves.length;await page.getByRole('button',{name:'pages.client.submitAdd',exact:true}).click();await page.waitForFunction(()=>!clientModal.visible&&!clientModal.confirmLoading);assert.equal(saves.length,beforeSave+1);
   const submitted=JSON.parse(saves.at(-1).data.settings);assert.deepEqual(submitted.clients,[clone(added.client)]);
   if(protocol==='shadowtls'){assert.ok(submitted.inner);assert.equal(submitted.inner.settings.clients.length,1);assert.equal(submitted.inner.settings.clients[0].email,added.client.email);assert.equal(submitted.inner.settings.password,undefined,'add route must not send server key');}

  });
 }
 for(const call of calls){assert.equal(call.contentType,'application/json');assert.equal(call.path,'/review/panel/api/server/native/credentials');}
 await check('optional-dnstt-socks-roundtrip-preserves-credentials',async()=>{
  await load();await openNew('dnstt');await settled();const original=await state();
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='inner.protocol'),'socks'));await settled();const socks=await state();assert.deepEqual(socks.errors,[]);assert.ok(socks.json.settings.clients[0].username&&socks.json.settings.clients[0].password);assert.equal(socks.json.settings.clients[0].id,undefined);
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='inner.protocol'),'vless'));await settled();const vless=await state();assert.deepEqual(vless.errors,[]);assert.equal(vless.json.settings.clients[0].id,original.json.settings.clients[0].id);assert.equal(vless.json.settings.privateKey,original.json.settings.privateKey);
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='inner.protocol'),'socks'));await settled();assert.equal((await state()).json.settings.clients[0].password,socks.json.settings.clients[0].password);
 });
 await check('optional-openvpn-proof-all-clients',async()=>{
  await load();await openNew('openvpn');await settled();await page.getByRole('button',{name:/Add client$/}).click();await page.waitForFunction(()=>!inModal.inbound.settings.generating);const before=await state();
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='clientProof.required'),true));await settled();const after=await state();assert.deepEqual(after.errors,[]);assert.equal(after.json.settings.clients.length,2);const ids=new Set();
  after.json.settings.clients.forEach((client,i)=>{assert.match(client.clientProof.key,/^[a-f0-9]{64}$/i);assert.ok(client.clientProof.keyId);ids.add(client.clientProof.keyId);assert.equal(client.privateKey,before.json.settings.clients[i].privateKey);});assert.equal(ids.size,2);
 });
 await check('optional-shadowtls-inner-roundtrip-preserves-keys',async()=>{
  await load();await openNew('shadowtls');await settled();const original=await state();
  for(const mode of ['socks','vless','shadowsocks']){await page.evaluate(mode=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='inner.protocol'),mode),mode);await settled();const s=await state();assert.deepEqual(s.errors,[]);assert.equal(s.json.settings.clients[0].password,original.json.settings.clients[0].password);complete('shadowtls',s.json.settings);}
  assert.deepEqual((await state()).json.settings.inner,original.json.settings.inner,'restored SS2022 credentials must be unchanged');
 });
 await check('optional-orbit-reality-roundtrip-core-valid',async()=>{
  await load();await openNew('orbit');await settled();const original=await state();
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='security'),'reality'));await settled();const pendingReality=await state();assert.ok(!pendingReality.json.settings.reality.serverNames?.length&&!pendingReality.json.settings.reality.dest,'Reality deployment names and destination must remain blank');await changeNativeField('reality.serverNames','cover.review.test');await changeNativeField('reality.dest','127.0.0.1:443');const reality=await state();assert.deepEqual(reality.errors,[]);assert.match(reality.json.settings.reality.privateKey,/^[A-Za-z0-9_-]{43}$/);assert.equal(reality.json.settings.clients[0].key,original.json.settings.clients[0].key);
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='security'),''));await settled();const restored=await state();assert.deepEqual(restored.errors,[]);assert.equal(restored.json.settings.clients[0].key,original.json.settings.clients[0].key);
  validateOrbitSettings(restored.json.settings,'orbit-reality-roundtrip');
  assert.equal(restored.json.settings.reality,undefined,'inactive Reality settings must not be emitted for ordinary TLS');
  await page.evaluate(()=>inModal.inbound.settings.setField(inModal.inbound.settings.fields.find(f=>f.path==='security'),'reality'));await settled();assert.deepEqual((await state()).json.settings.reality,reality.json.settings.reality,'switching back must preserve Reality keys');
 });
 await check('optional-orbit-websocket-roundtrip-core-valid',async()=>{
  await load();await openNew('orbit');await settled();const original=await state();
  await changeNativeField('transport','ws');const missingWS=await state();assert.ok(!missingWS.json.settings.host&&!missingWS.json.settings.clientExport?.serverName,'WS Host and peer must remain blank');assert.ok(missingWS.errors.length);await changeNativeField('host','ws.review.test');await changeNativeField('clientExport.serverName','127.0.0.1');const ws=await state();assert.deepEqual(ws.errors,[]);assert.ok(ws.json.settings.host&&ws.json.settings.path);validateOrbitSettings(ws.json.settings,'orbit-ws');
  await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible&&app.dbInbounds.length===1);await page.evaluate(()=>app.openEditInbound(app.dbInbounds[0].id));
  await changeNativeField('transport','tcp');const tcp=await state();assert.deepEqual(tcp.errors,[]);validateOrbitSettings(tcp.json.settings,'orbit-ws-to-tcp');assert.ok(!tcp.json.settings.host&&!tcp.json.settings.path);assert.equal(tcp.json.settings.clients[0].key,original.json.settings.clients[0].key);
  await changeNativeField('transport','ws');const again=await state();assert.equal(again.json.settings.host,ws.json.settings.host);assert.equal(again.json.settings.path,ws.json.settings.path);
 });
 await check('optional-orbit-wss-to-ws-preserves-dormant-certificate',async()=>{
  await load();await openNew('orbit');await settled();const original=await state();
  await changeNativeField('transport','wss');await changeNativeField('host','ws.review.test');await changeNativeField('clientExport.serverName','127.0.0.1');await changeNativeField('outerTls.certificate',original.json.settings.tls.certificate.join('\n'));await changeNativeField('outerTls.key',original.json.settings.tls.key.join('\n'));const wss=await state();assert.deepEqual(wss.errors,[]);validateOrbitSettings(wss.json.settings,'orbit-wss-fixture');
  await changeNativeField('transport','ws');const ws=await state();assert.deepEqual(ws.errors,[]);validateOrbitSettings(ws.json.settings,'orbit-wss-to-ws');assert.equal(ws.json.settings.outerTls,undefined);
  await changeNativeField('transport','wss');const restored=await state();assert.deepEqual(restored.json.settings.outerTls,wss.json.settings.outerTls);assert.deepEqual(restored.errors,[]);validateOrbitSettings(restored.json.settings,'orbit-wss-restored');
 });
 await check('optional-orbit-wss-tcp-quic-wss-core-valid',async()=>{
  await load();await openNew('orbit');await settled();const original=await state();
  await changeNativeField('transport','wss');await changeNativeField('host','ws.review.test');await changeNativeField('clientExport.serverName','127.0.0.1');await changeNativeField('outerTls.certificate',original.json.settings.tls.certificate.join('\n'));await changeNativeField('outerTls.key',original.json.settings.tls.key.join('\n'));await changeNativeField('clientExport.serverName','127.0.0.1');const wss=await state();assert.deepEqual(wss.errors,[]);validateOrbitSettings(wss.json.settings,'orbit-wss-start');
  for(const mode of ['tcp','quic']){await changeNativeField('transport',mode);const s=await state();assert.deepEqual(s.errors,[]);assert.ok(!s.json.settings.host&&!s.json.settings.path&&!s.json.settings.outerTls);assert.equal(s.json.settings.clientExport?.serverName,undefined);assert.equal(s.json.settings.clients[0].key,wss.json.settings.clients[0].key);validateOrbitSettings(s.json.settings,'orbit-wss-to-'+mode);}
  await changeNativeField('transport','wss');const restored=await state();assert.deepEqual(restored.errors,[]);assert.deepEqual(restored.json.settings.outerTls,wss.json.settings.outerTls);assert.equal(restored.json.settings.host,wss.json.settings.host);assert.equal(restored.json.settings.path,wss.json.settings.path);assert.equal(restored.json.settings.clientExport.serverName,wss.json.settings.clientExport.serverName);validateOrbitSettings(restored.json.settings,'orbit-wss-final-restored');
 });
 for(const protocol of protocols){await check('actual-clone-submit-'+protocol,async()=>{
  await load();await openNew(protocol);await settled();const original=await state();
  await page.locator('.ant-modal:visible .ant-modal-footer button.ant-btn-primary').click();await page.waitForFunction(()=>!inModal.visible&&app.dbInbounds.length===1);const count=calls.length,before=saves.length;
  await page.evaluate(async()=>{const db=app.dbInbounds[0];await app.cloneInbound(db.toInbound(),db);});assert.equal(saves.length,before+1);assert.equal(calls.length,count,'clone must not generate replacement cryptography');const copied=JSON.parse(saves.at(-1).data.settings);assert.notEqual(copied.clients[0].email,original.json.settings.clients[0].email);assert.notEqual(copied.clients[0].subId,original.json.settings.clients[0].subId);complete(protocol,copied);
  for(const key of ['privateKey','tls','certificates'])assert.deepEqual(copied[key],original.json.settings[key]);
  for(const key of ['password','id','username','key','commonName','privateKey','certificate'])assert.equal(copied.clients[0][key],original.json.settings.clients[0][key]);
  if(protocol==='anytls')assert.deepEqual(JSON.parse(saves.at(-1).data.streamSettings).tlsSettings,original.json.streamSettings.tlsSettings);
 });}
 await check('standalone-shadowtls-email-binding-at-submit',async()=>{
  await load();await openNew('shadowtls');await settled();const initial=await state();const row=rowFor('shadowtls',{settings:initial.json.settings});
  await page.evaluate(row=>{inModal.close();app.setInbounds([row]);app.openAddClient(row.id);},row);
  await page.waitForFunction(()=>clientModal.visible&&!clientModal.inbound.settings.generating&&!clientModal.initializing);
  await page.evaluate(()=>{clientModalApp.client.email='renamed-second@example.invalid';});
  const before=saves.length;await page.getByRole('button',{name:'pages.client.submitAdd',exact:true}).click();await page.waitForFunction(()=>!clientModal.visible);assert.equal(saves.length,before+1);
  const submitted=JSON.parse(saves.at(-1).data.settings);assert.equal(submitted.clients[0].email,'renamed-second@example.invalid');assert.equal(submitted.inner.settings.clients[0].email,'renamed-second@example.invalid');assert.equal(submitted.inner.settings.clients.length,1);assert.equal(submitted.inner.settings.password,undefined);
 });
 }finally{
  const report={passed:results.filter(r=>r.ok).length,failed:results.filter(r=>!r.ok).length,results,pageErrors:errors,credentialRequests:calls.length,source:'complete Go-rendered page, actual production credential service; persistence HTTP fixture',sourceBefore,sourceAfter:sourceHashes(),sourceStable:JSON.stringify(sourceBefore)===JSON.stringify(sourceHashes())};
  fs.writeFileSync(path.join(work,'captured-posts.json'),JSON.stringify(saves,null,2),{mode:0o600});fs.writeFileSync(path.join(work,'results.json'),JSON.stringify(report,null,2));console.log('RESULTS '+path.join(work,'results.json'));
  if(browser)await browser.close();await new Promise(r=>server.close(r));
 }
 if(results.some(r=>!r.ok))process.exitCode=1;
})().catch(e=>{console.error(e);process.exitCode=1;});
