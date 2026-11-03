'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.resolve(__dirname, '../../web/html/index.html'), 'utf8');
const start = html.indexOf('      importDatabase() {');
const end = html.indexOf('      startPolling() {', start);
assert.ok(start >= 0 && end > start);
const method = html.slice(start, end);
function fixture(response) {
    const calls = [], sleeps = [], messages = [];
    const location = {href:'https://panel.example/old/panel/',assign(url){this.assigned=url;},reload(){this.reloaded=true;}};
    const picker = {addEventListener(event,callback){this[event]=callback;},click(){this.clicked=true;}};
    const context = vm.createContext({URL,location,
        document:{createElement:()=>picker},
        FormData:class {constructor(){this.values=new Map();}append(key,value){this.values.set(key,value);}},
        backupModal:{hide(){}},
        HttpUtil:{async post(url,body){calls.push({url,body});return url.endsWith('/importDB')?response:{success:true};}},
        PromiseUtil:{async sleep(ms){sleeps.push(ms);}},
    });
    const methods = vm.runInContext('({' + method + '})',context);
    methods.loading=()=>{};
    methods.$message={success:message=>messages.push(message),warning:message=>messages.push(message)};
    methods.importDatabase();
    return {picker,calls,sleeps,messages,location};
}
test('portable restore uses the announced URL and never sends a second restart',async()=>{
    const f=fixture({success:true,obj:{restored:true,restarting:true,restartAfterSeconds:3,url:'https://panel.example/new/panel/'}});
    assert.equal(f.picker.accept,'.zip,.db');
    await f.picker.change({target:{files:[{name:'backup.zip'}]}});
    assert.deepEqual(f.calls.map(call=>call.url),['/panel/api/server/importDB']);
    assert.equal(f.location.assigned,'https://panel.example/new/panel/');
    assert.deepEqual(f.sleeps,[5000]);
    assert.match(f.messages[0],/Backup restored/);
});
test('legacy response keeps the existing explicit restart behavior',async()=>{
    const f=fixture({success:true});
    await f.picker.change({target:{files:[{name:'legacy.db'}]}});
    assert.deepEqual(f.calls.map(call=>call.url),['/panel/api/server/importDB','/panel/setting/restartPanel']);
    assert.equal(f.location.reloaded,true);
});
test('failed restore and cancelled picker never restart or redirect',async()=>{
    const f=fixture({success:false});
    await f.picker.change({target:{files:[]}});
    assert.equal(f.calls.length,0);
    await f.picker.change({target:{files:[{name:'invalid.zip'}]}});
    assert.equal(f.calls.length,1);
    assert.equal(f.location.assigned,undefined);
    assert.equal(f.location.reloaded,undefined);
});
test('restore redirect rejects executable URLs and bounds the announced delay',async()=>{
    const f=fixture({success:true,obj:{restored:true,restarting:true,restartAfterSeconds:99999,url:'javascript:alert(1)'}});
    await f.picker.change({target:{files:[{name:'backup.zip'}]}});
    assert.equal(f.location.assigned,f.location.href);
    assert.deepEqual(f.sleeps,[32000]);
});


test('manual restart fallback preserves restored success and the new panel URL',async()=>{
    const f=fixture({success:true,obj:{restored:true,restarting:false,restartRequired:true,url:'/new/panel/'}});
    await f.picker.change({target:{files:[{name:'backup.zip'}]}});
    assert.deepEqual(f.calls.map(call=>call.url),['/panel/api/server/importDB','/panel/setting/restartPanel']);
    assert.equal(f.location.assigned,'https://panel.example/new/panel/');
    assert.match(f.messages[0],/Backup restored/);
});
