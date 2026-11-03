'use strict';
// Entire Go-rendered inbounds page, real local Vue/Ant/models/application scripts.
// Only HTTP API data and WebSocket transport are fixtures; no UI methods are mocked.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {execFileSync}=require('node:child_process');
const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'../..');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'d11-full-inbounds-'));
const override=process.env.INBOUNDS_TEMPLATE_OVERRIDE||'';
const helper=path.join(temp,'render.go');
fs.writeFileSync(helper,`package main
import("html/template";"os";"path/filepath";"strings";"fmt")
func main(){root:=os.Args[1]; override:=os.Args[2]; t:=template.New("").Funcs(template.FuncMap{"i18n":func(key string,args ...string)string{return key}});err:=filepath.WalkDir(filepath.Join(root,"web/html"),func(p string,d os.DirEntry,e error)error{if e!=nil{return e};if d.IsDir()||!strings.HasSuffix(p,".html"){return nil};data,e:=os.ReadFile(p);if override!=""&&p==filepath.Join(root,"web/html/inbounds.html"){data,e=os.ReadFile(override)};if e!=nil{return e};_,e=t.New(filepath.Base(p)).Parse(string(data));return e});if err!=nil{panic(err)};err=t.ExecuteTemplate(os.Stdout,"inbounds.html",map[string]any{"base_path":"/fixture/","cur_ver":"test","host":"127.0.0.1","title":"menu.inbounds","request_uri":"/fixture/panel/inbounds","lang":"en-US"});if err!=nil{panic(fmt.Sprint(err))}}
`);
const rendered=execFileSync('go',['run',helper,root,override],{encoding:'utf8',maxBuffer:8<<20,env:{...process.env,GOMAXPROCS:'2'}});
const UUID='00112233-4455-4677-8899-aabbccddeeff';
function inbound(id,protocol,remark,enable=true){
 const client={email:remark+'@example.invalid',enable:true,id:UUID,password:'synthetic-'+id,subId:'sub-'+id,totalGB:0,expiryTime:0,limitIp:0,flow:'',security:'auto',reset:0};
 const settings=protocol==='vless'?{clients:[client],decryption:'none',encryption:'none'}:{clients:[client],handshakeTimeout:27,clientExport:{serverName:'trusted.example.invalid'},futureContract:{retain:'native-settings'}};
 return {id,userId:1,up:100,down:200,allTime:300,total:0,remark,enable,expiryTime:0,listen:'127.0.0.1',port:29000+id,protocol,settings:JSON.stringify(settings),streamSettings:JSON.stringify({network:'tcp',security:'none'}),tag:'inbound-'+id,sniffing:'{}',clientStats:[{id,inboundId:id,email:client.email,enable:true,up:100,down:200,total:0,expiryTime:0,allTime:300}],trafficReset:'never',lastTrafficResetTime:0};
}
const legacy=inbound(1,'vless','Legacy Alpha'),native=inbound(2,'anytls','Native Beta'),disabled=inbound(3,'vless','Disabled Gamma',false),disabledNative=inbound(4,'anytls','Native Disabled Delta',false);
let dataset=[],subMode={classic:true,json:true};
const defaults=()=>({expireDiff:0,trafficDiff:0,defaultCert:'',defaultKey:'',tgBotEnable:false,subEnable:subMode.classic,subTitle:'Fixture',subURI:'https://subscriptions.example.invalid/sub/',subJsonURI:'https://subscriptions.example.invalid/json/',subJsonEnable:subMode.json,pageSize:25,remarkModel:'-ieo',datepicker:'gregorian',ipLimitEnable:false});
const server=http.createServer((req,res)=>{
 const url=new URL(req.url,'http://127.0.0.1');
 if(url.pathname==='/fixture/panel/inbounds'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(rendered);return;}
 if(url.pathname.startsWith('/fixture/assets/')){
  const file=path.resolve(root,'web',url.pathname.slice('/fixture/'.length));
  if(!file.startsWith(path.join(root,'web/assets')+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.woff2')?'font/woff2':'application/octet-stream');fs.createReadStream(file).pipe(res);return;
 }
 let obj;
 if(url.pathname.endsWith('/panel/api/inbounds/list'))obj=dataset;
 else if(url.pathname.endsWith('/panel/api/inbounds/onlines'))obj=[];
 else if(url.pathname.endsWith('/panel/api/inbounds/lastOnline'))obj={};
 else if(url.pathname.endsWith('/panel/setting/defaultSettings'))obj=defaults();
 else if(url.pathname.endsWith('/panel/api/server/status'))obj={xray:{state:'running'}};
 else if(url.pathname==='/favicon.ico'){res.writeHead(204);res.end();return;}
 else{res.writeHead(404);res.end('Unexpected fixture request: '+url.pathname);return;}
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify({success:true,obj}));
});
const checks=[];let browser;
function visibleMenu(page){return page.locator('.ant-dropdown:visible .ant-dropdown-menu').last();}
async function openGlobal(page){await page.getByRole('button',{name:/pages\.inbounds\.generalActions$/}).click();await visibleMenu(page).waitFor({state:'visible'});await page.waitForTimeout(180);return visibleMenu(page);}
async function closeModal(page){await page.evaluate(()=>{if(typeof txtModal!=='undefined')txtModal.visible=false;});await page.keyboard.press('Escape');await page.locator('#app').click({position:{x:800,y:20}});}
async function closeMenu(page){await page.locator('#app').click({position:{x:800,y:20}});await page.waitForTimeout(250);}
async function modalText(page){await page.locator('.ant-modal:visible textarea').waitFor({state:'visible'});return page.locator('.ant-modal:visible textarea').inputValue();}
(async()=>{
 try{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROME||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
  const base='http://127.0.0.1:'+server.address().port;
  for(const [name,rows] of [['empty',[]],['legacy',[legacy]],['native',[native]],['mixed',[legacy,native,disabled,disabledNative]]]){
   dataset=rows;subMode={classic:true,json:true};
   const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
   await page.addInitScript(()=>{localStorage.setItem('isRefreshEnabled','false');window.WebSocket=class{static OPEN=1;static CLOSED=3;constructor(){this.readyState=1;setTimeout(()=>this.onopen?.({}),10);}send(){}close(){this.readyState=3;}};});
   await page.goto(base+'/fixture/panel/inbounds');
   await page.waitForFunction(()=>typeof app!=='undefined'&&app.loadingStates.fetched&&!app.loadingStates.spinning,{},{timeout:10000});
   await page.waitForTimeout(150);
   assert.deepEqual(errors,[],name+' whole-page Vue errors');
   assert.equal(await page.locator('#app .ant-card').count()>=2,true,name+' statistics and inbounds card');
   assert.equal(await page.locator('#app .ant-table-wrapper').count(),1,name+' full table rendered');
   assert.equal(await page.getByRole('button',{name:/pages\.inbounds\.addInbound$/}).isVisible(),true,name+' add toolbar');
   assert.equal(await page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').count(),rows.length,name+' rows rendered');
   assert.equal(await page.evaluate(()=>app.total.clients),rows.length,name+' total client count');
   for(const row of rows)assert.equal(await page.evaluate(id=>app.clientCount[id]?.clients,row.id),1,name+' client count '+row.protocol);
   let menu=await openGlobal(page);
   assert.equal(await menu.getByText('pages.inbounds.export',{exact:true}).count(),1,name+' global export present');
   assert.equal(await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).count(),1,name+' global subscriptions present');
   await menu.getByText('pages.inbounds.export',{exact:true}).click();
   const allLinks=await modalText(page);
   if(rows.some(r=>r.protocol==='vless'))assert.match(allLinks,/vless:\/\//);
   assert.doesNotMatch(allLinks,/anytls:\/\//);
   await closeModal(page);
   menu=await openGlobal(page);await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).click();
   const subs=await modalText(page);
   for(const row of rows)assert.ok(subs.includes((row.protocol==='anytls'?'/json/':'/sub/')+'sub-'+row.id),name+' subscription uses correct endpoint');
   await closeModal(page);
   for(const row of rows){
    const tr=page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').filter({hasText:row.remark});
    await tr.locator('i.anticon-more').click();menu=visibleMenu(page);await menu.waitFor({state:'visible'});
    assert.equal(await menu.getByText('pages.inbounds.export',{exact:true}).count(),row.protocol==='anytls'?0:1,'row link visibility '+row.protocol);
    assert.equal(await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).count(),1,'row subscription visibility');
    await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).click();
    assert.ok((await modalText(page)).includes((row.protocol==='anytls'?'/json/':'/sub/')+'sub-'+row.id));await closeModal(page);
    const expand=tr.locator('.ant-table-row-expand-icon');if(await expand.count()){await expand.click();await page.waitForTimeout(50);assert.deepEqual(errors,[],'expanded client row '+row.protocol);await expand.click();}
   }
   if(name==='mixed'){
    const search=page.getByPlaceholder('search',{exact:true});await search.fill('Native Beta');await search.press('Tab');await page.waitForTimeout(650);
    assert.equal(await page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').count(),1,'search leaves native row');
    assert.deepEqual(await page.evaluate(()=>app.searchedInbounds[0].toInbound().settings.toJson().futureContract),{retain:'native-settings'},'native search retains non-client settings');
    await search.fill('');await search.press('Tab');await page.waitForTimeout(650);
    assert.equal(await page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').count(),4,'cleared search restores rows');
    await page.evaluate(()=>{app.enableFilter=true;app.toggleFilter();app.filterBy='deactive';app.filterInbounds();});await page.waitForTimeout(50);
    assert.equal(await page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').count(),2,'disabled filter includes native and legacy');
    assert.match(await page.locator('#app .ant-table-tbody').first().innerText(),/Disabled Gamma/);
    assert.match(await page.locator('#app .ant-table-tbody').first().innerText(),/Native Disabled Delta/);
    assert.deepEqual(await page.evaluate(()=>app.searchedInbounds.find(row=>row.protocol==='anytls').toInbound().settings.toJson().futureContract),{retain:'native-settings'},'native disabled filter retains settings');
    await page.evaluate(rows=>{app.onlineClients=['Native Beta@example.invalid'];app.setInbounds(rows);app.filterBy='online';app.filterInbounds();},rows);await page.waitForTimeout(50);
    assert.equal(await page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').count(),1,'online filter selects native account');
    assert.match(await page.locator('#app .ant-table-tbody').first().innerText(),/Native Beta/);
    assert.deepEqual(await page.evaluate(()=>app.searchedInbounds[0].toInbound().settings.toJson().futureContract),{retain:'native-settings'},'native online filter retains settings');
    await page.evaluate(()=>{app.enableFilter=false;app.toggleFilter();});
    for(const mode of [{classic:false,json:true},{classic:true,json:false},{classic:false,json:false}]){
     await page.evaluate(mode=>{app.subSettings.enable=mode.classic;app.subSettings.subJsonEnable=mode.json;},mode);
     menu=await openGlobal(page);assert.equal(await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).count(),mode.classic||mode.json?1:0,'global mode gate');await closeMenu(page);
     for(const row of [legacy,native]){const tr=page.locator('#app .ant-table-tbody').first().locator(':scope > tr.ant-table-row').filter({hasText:row.remark});await tr.locator('i.anticon-more').click();menu=visibleMenu(page);await menu.waitFor({state:'visible'});assert.equal(await menu.getByText('pages.inbounds.export - pages.settings.subSettings',{exact:true}).count(),(row.protocol==='anytls'?mode.json:mode.classic)?1:0,'row mode gate '+row.protocol);await closeMenu(page);}
    }
   }
   assert.deepEqual(errors,[],name+' final Vue errors');checks.push({dataset:name,rows:rows.length,fullPage:true,toolbar:true,globalExports:true,rowMenus:true,clientExpansion:true,searchFilter:name==='mixed'});await page.close();
  }
  console.log(JSON.stringify({passed:true,template:override||'worktree/inbounds.html',checks},null,2));
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
