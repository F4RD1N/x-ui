'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.resolve(__dirname, '../../web/html/index.html'), 'utf8');
const begin = html.indexOf('      async updatePanel() {');
const end = html.indexOf('      openGeofiles() {', begin);
assert.ok(begin >= 0 && end > begin);
const dataStart = html.indexOf('      panelUpdate: {');
const dataEnd = html.indexOf('      logModal,', dataStart);
const destroyStart = html.indexOf('    beforeDestroy() {');
const destroyEnd = html.indexOf('    async mounted() {', destroyStart);
const next = '2.9.0-dialect.11.6';
const status = (state = 'running', extra = {}) => ({id:'job-1',state,phase:'installing',currentVersion:next,...extra});
const envelope = obj => ({data:{success:true,obj}});
const deferred = () => {let resolve, reject; const promise = new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const flush = () => new Promise(resolve => setImmediate(resolve));

function fixture(options = {}) {
  const calls=[], messages=[], confirms=[], timers=new Map();
  let now=0, timerID=0, gets=0, reloads=0;
  const context = vm.createContext({AbortController, Promise,
    Date:{now:()=>now},
    setTimeout(fn,delay){const id=++timerID;timers.set(id,{fn,at:now+delay});return id;},
    clearTimeout(id){timers.delete(id);},
    window:{location:{reload(){reloads++;}}},
    themeSwitcher:{currentTheme:'dark'},
    HttpUtil:{async get(url,unused,config){calls.push({method:'check',url,config});
      if(options.check instanceof Error) throw options.check;
      return options.check ?? {success:true,obj:{current:'2.9.0-dialect.11.5',latest:next,available:true}};
    }},
    axios:{
      async post(url,body,config){calls.push({method:'post',url,config});
        if(options.post instanceof Error) throw options.post;
        return typeof options.post==='function'?options.post():options.post??envelope(status());
      },
      async get(url,config){calls.push({method:'get',url,config});
        let value=typeof options.get==='function'?options.get(gets++,config):options.get?.[gets++];
        if(value instanceof Error)throw value;
        if(value===undefined)value=status('succeeded');
        return value?.data?value:envelope(await value);
      },
    },
  });
  const methods=vm.runInContext('({' + html.slice(begin,end) + '})',context);
  methods.panelUpdate=vm.runInContext('({' + html.slice(dataStart,dataEnd) + '})',context).panelUpdate;
  methods.$confirm=value=>confirms.push(value);
  methods.$message=Object.fromEntries(['info','warning','error','success'].map(kind=>[kind,text=>messages.push({kind,text})]));
  const destroy=vm.runInContext('({' + html.slice(destroyStart,destroyEnd) + '})',context).beforeDestroy;
  return {methods,calls,messages,confirms,timers,
    get reloads(){return reloads;},
    advance(ms){now+=ms;},
    destroy(){destroy.call(methods);},
    async tick(){await flush();if(timers.size){const [id,timer]=[...timers].sort((a,b)=>a[1].at-b[1].at)[0];timers.delete(id);now=Math.max(now,timer.at);timer.fn();}await flush();},
    async drain(limit=600){for(let n=0;n<limit;n++){await flush();if(!methods.panelUpdate.busy&&!timers.size)return;await this.tick();}throw new Error('UI did not finish within bounded virtual polling');},
    async start(){await methods.updatePanel();assert.equal(confirms.length,1);await confirms[0].onOk();await flush();},
  };
}

for(const [name,check] of [['thrown check',new Error('offline')],['rejected check',{success:false}],['malformed check',{success:true,obj:{}}]]) {
  test(name+' clears checking state without posting',async()=>{const f=fixture({check});await f.methods.updatePanel();assert.equal(f.methods.panelUpdate.busy,false);assert.equal(f.confirms.length,0);assert.equal(f.calls.filter(x=>x.method==='post').length,0);});
}
test('latest version and confirmation cancellation leave no busy state',async()=>{
  const latest=fixture({check:{success:true,obj:{current:next,latest:next,available:false}}});
  await latest.methods.updatePanel();assert.equal(latest.methods.panelUpdate.busy,false);assert.equal(latest.confirms.length,0);
  const f=fixture();await f.methods.updatePanel();await f.methods.updatePanel();assert.equal(f.confirms.length,1);f.confirms[0].onCancel();assert.equal(f.methods.panelUpdate.confirmationOpen,false);assert.equal(f.calls.filter(x=>x.method==='post').length,0);
});
test('one accepted POST progresses until matching terminal version before success/reload',async()=>{
  const f=fixture({get:[status('running',{phase:'downloading'}),status('running',{currentVersion:next}),status('succeeded',{currentVersion:'v'+next})]});
  await f.start();assert.equal(f.methods.panelUpdate.busy,true);assert.equal(f.reloads,0);assert.equal(f.messages.filter(x=>x.kind==='success').length,0);
  await f.tick();assert.equal(f.reloads,0);assert.equal(f.messages.filter(x=>x.kind==='success').length,0);
  await f.drain();assert.equal(f.reloads,1);assert.equal(f.methods.panelUpdate.busy,false);assert.equal(f.methods.panelUpdate.available,false);
  assert.equal(f.calls.filter(x=>x.method==='post').length,1);
  assert.equal(f.calls.find(x=>x.method==='post').config.timeout,35000);
  assert.ok(f.calls.filter(x=>x.method==='get').every(x=>x.config.timeout===5000&&x.config.signal));
});
test('double confirmation while acceptance is pending cannot duplicate POST',async()=>{
  const waiting=deferred();const f=fixture({post:()=>waiting.promise});await f.methods.updatePanel();
  const first=f.confirms[0].onOk();await flush();await f.confirms[0].onOk();assert.equal(f.calls.filter(x=>x.method==='post').length,1);
  waiting.resolve(envelope(status()));await first;await f.drain();assert.equal(f.reloads,1);
});
for(const phase of ['finished','interrupted'])test('terminal '+phase+' failure clears busy without success',async()=>{
  const f=fixture({get:[status('failed',{phase,exitCode:1})]});await f.start();await f.drain();assert.equal(f.reloads,0);assert.equal(f.methods.panelUpdate.busy,false);assert.ok(f.messages.some(x=>x.kind==='error'));assert.ok(!f.messages.some(x=>x.kind==='success'));
});
test('rejected busy POST displays safe server message and resumes via GET only',async()=>{
  const f=fixture({post:{data:{success:false,msg:'a panel update is already running; wait for it to finish'}},get:[status(),status('succeeded')]});
  await f.start();await f.drain();assert.equal(f.calls.filter(x=>x.method==='post').length,1);assert.equal(f.reloads,1);assert.ok(f.messages.some(x=>x.text.includes('already running')));assert.ok(f.messages.some(x=>x.kind==='success'&&x.text.includes('Running version:')));
});
test('lost acceptance response attaches to running persisted job without reposting',async()=>{
  const f=fixture({post:new Error('response lost'),get:[status(),status('succeeded')]});await f.start();await f.drain();assert.equal(f.calls.filter(x=>x.method==='post').length,1);assert.equal(f.reloads,1);assert.ok(!f.messages.some(x=>x.text.includes('result is unknown')));
});
test('lost response with unavailable status stays uncertain and releases busy',async()=>{
  const f=fixture({post:new Error('response lost'),get:()=>{throw new Error('offline');}});await f.start();await f.drain();assert.equal(f.reloads,0);assert.equal(f.calls.filter(x=>x.method==='post').length,1);assert.ok(f.messages.some(x=>x.kind==='warning'&&x.text.includes('may still be running')));
});
test('legacy acceptance without an ID never becomes unbounded polling',async()=>{
  const f=fixture({post:{data:{success:true}}});await f.start();await f.drain();assert.equal(f.calls.filter(x=>x.method==='get').length,0);assert.equal(f.reloads,0);assert.ok(f.messages.some(x=>x.kind==='warning'));
});
test('temporary restart/offline GET failures recover quietly without POST retry',async()=>{
  const f=fixture({get:[new Error('offline'),new Error('offline'),status(),status('succeeded')]});await f.start();await f.drain();assert.equal(f.reloads,1);assert.equal(f.calls.filter(x=>x.method==='post').length,1);assert.ok(!f.messages.some(x=>x.kind==='error'||x.kind==='warning'));
});
test('permanent offline status stops after twelve bounded requests',async()=>{
  const f=fixture({get:()=>{throw new Error('offline');}});await f.start();await f.drain();assert.equal(f.calls.filter(x=>x.method==='get').length,12);assert.equal(f.reloads,0);assert.ok(f.messages.some(x=>x.kind==='warning'&&x.text.includes('result is unknown')));
});
for(const value of [status('succeeded',{id:'newer-job'}),{state:'succeeded',currentVersion:next},status('idle')])test('missing/replaced/idle job never claims update success '+JSON.stringify(value),async()=>{
  const f=fixture({get:[value]});await f.start();await f.drain();assert.equal(f.reloads,0);assert.ok(!f.messages.some(x=>x.kind==='success'));assert.ok(f.messages.some(x=>x.kind==='warning'));
});
test('terminal success with unexpected version remains unverified',async()=>{
  const f=fixture({get:[status('succeeded',{currentVersion:'old'})]});await f.start();await f.drain();assert.equal(f.reloads,0);assert.ok(f.messages.some(x=>x.kind==='warning'&&x.text.includes('not confirmed')));
});
test('malformed status envelopes are bounded and cannot cause false success',async()=>{
  const f=fixture({get:()=>({data:{success:true,obj:{state:'unknown'}}})});await f.start();await f.drain();assert.equal(f.calls.filter(x=>x.method==='get').length,12);assert.equal(f.reloads,0);assert.ok(!f.messages.some(x=>x.kind==='success'));
});
test('running job reaches absolute monitoring deadline with no endless busy',async()=>{
  const f=fixture({get:()=>status()});await f.start();f.advance(15*60*1000);await f.tick();await f.drain();assert.equal(f.methods.panelUpdate.busy,false);assert.equal(f.reloads,0);assert.ok(f.messages.some(x=>x.kind==='warning'&&x.text.includes('timed out')));
});
test('page reload can resume current running job without posting or asserting intended version',async()=>{
  const f=fixture({get:[status(),status('succeeded',{currentVersion:'observed-version'})]});assert.equal(await f.methods.resumePanelUpdate(),true);await f.drain();assert.equal(f.calls.filter(x=>x.method==='post').length,0);assert.equal(f.reloads,1);assert.ok(f.messages.some(x=>x.kind==='success'&&x.text.includes('observed-version')));
});
test('page mount shows last failure but idle/succeeded or unreachable state do not auto-update',async()=>{
  for(const get of [[status('failed',{phase:'interrupted'})],[status('succeeded')],[{state:'idle'}],()=>{throw new Error('offline');}]){
    const f=fixture({get});await f.methods.resumePanelUpdate();await f.drain();assert.equal(f.calls.filter(x=>x.method==='post').length,0);assert.equal(f.reloads,0);assert.equal(f.methods.panelUpdate.busy,false);
  }
});
test('component destruction clears pending timer and prevents further polling',async()=>{
  const f=fixture({get:()=>status()});await f.start();assert.equal(f.timers.size,1);const count=f.calls.length;f.destroy();await flush();assert.equal(f.timers.size,0);assert.equal(f.methods.panelUpdate.busy,false);assert.equal(f.calls.length,count);assert.equal(f.reloads,0);
});
test('component destruction aborts pending GET and ignores stale success',async()=>{
  const waiting=deferred();const f=fixture({get:()=>waiting.promise});await f.start();const request=f.calls.find(x=>x.method==='get');f.destroy();assert.equal(request.config.signal.aborted,true);waiting.resolve(status('succeeded'));await flush();assert.equal(f.reloads,0);assert.equal(f.methods.panelUpdate.busy,false);assert.ok(!f.messages.some(x=>x.kind==='success'));
});
test('component destruction during POST ignores late acceptance without polling',async()=>{
  const waiting=deferred();const f=fixture({post:()=>waiting.promise});await f.methods.updatePanel();const pending=f.confirms[0].onOk();await flush();f.destroy();waiting.resolve(envelope(status()));await pending;assert.equal(f.calls.filter(x=>x.method==='get').length,0);assert.equal(f.reloads,0);assert.equal(f.methods.panelUpdate.busy,false);
});
test('component destruction during update check cannot open a late confirmation',async()=>{
  const waiting=deferred();const f=fixture({check:waiting.promise});const pending=f.methods.updatePanel();await flush();f.destroy();waiting.resolve({success:true,obj:{current:'old',latest:next,available:true}});await pending;assert.equal(f.confirms.length,0);assert.equal(f.methods.panelUpdate.busy,false);assert.equal(f.calls.filter(x=>x.method==='post').length,0);
});
test('page mount invokes only the read-only resume path',()=>{
  assert.match(html.slice(destroyEnd,destroyEnd+160),/async mounted\(\)\s*\{\s*this\.resumePanelUpdate\(\);/);
});
