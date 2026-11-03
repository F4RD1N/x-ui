#!/usr/bin/env python3
"""Replay exact browser-captured native mutation bodies into disposable real panels.

Run with --netns; each captured scenario starts with a fresh SQLite database.
Credential/material/port fields are never normalized or repaired by this runner.
"""
import argparse, importlib.util, json, os, pathlib, subprocess, sys, time
sys.dont_write_bytecode=True
os.environ['PYTHONDONTWRITEBYTECODE']='1'
HERE=pathlib.Path(__file__).resolve().parent
if '--netns' in sys.argv:
    os.environ['D11_HOST_NETNS']=os.readlink('/proc/self/ns/net')
    argv=[str(a) for a in sys.argv[1:] if a!='--netns']
    os.execvp('unshare',['unshare','--net','python3',str(pathlib.Path(__file__).resolve()),*argv])
assert os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['D11_HOST_NETNS'], 'private network namespace required'
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','address','add','198.18.0.1/32','dev','lo'],check=True)
spec=importlib.util.spec_from_file_location('panel_e2e',HERE/'panel-e2e.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
p=argparse.ArgumentParser();p.add_argument('--panel',type=pathlib.Path,required=True);p.add_argument('--core',type=pathlib.Path,required=True);p.add_argument('--captured',type=pathlib.Path,required=True);p.add_argument('--work',type=pathlib.Path,required=True);p.add_argument('--case-prefix',help='Replay only captured cases with this explicit prefix');args=p.parse_args()
assert not args.work.exists();args.work.mkdir(mode=0o700,parents=True)
posts=json.loads(args.captured.read_text());groups={}
for post in posts:
    if post['case'].startswith(args.case_prefix if args.case_prefix else ('standalone-add-client-','actual-clone-submit-','telegram-input-validation')):
        groups.setdefault(post['case'],[]).append(post)
assert len(groups)>=(1 if args.case_prefix else 12), 'need matching focused cases, or all six Add Client and all six clone cases'
results=[]
def record(name,ok,detail=''):
    results.append({'name':name,'ok':ok,'detail':str(detail)[:1500]});print(('PASS ' if ok else 'FAIL ')+name+(': '+str(detail)[:250] if detail else ''),flush=True)
try:
    for name, captured in groups.items():
        folder=args.work/name;folder.mkdir(mode=0o700)
        panel=h.Panel(folder,args.panel.resolve(),args.core.resolve());panel.init();panel.start()
        try:
            for index,post in enumerate(captured):
                # Only URL base path changes. The full captured form body is sent unchanged.
                route=post['path'].removeprefix('/review')
                obj=panel.api('POST',route,data=post['rawBody'],headers={'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8','X-Requested-With':'XMLHttpRequest'})
                record(name+f'.post{index+1}',True,route)
                if 'responseId' in post:
                    assert obj['id']==post['responseId'], 'fresh DB ID differs from browser fixture; payload was not rewritten'
                rows=panel.api('GET','/panel/api/inbounds/list')
                assert rows,'mutation not persisted'
                if route.endswith('/add'):
                    submitted=json.loads(post['data']['settings'])
                    saved=json.loads(next(r for r in rows if r['id']==obj['id'])['settings'])
                    # Deployment input and generated material must survive the
                    # real storage boundary exactly, including explicit DNS [].
                    for key in ('domain','host','path','reality','handshake','tunnel','clientExport','tls','outerTls','certificates'):
                        assert saved.get(key)==submitted.get(key), 'saved deployment/material field differs: '+key
                if route.endswith('/addClient'):
                    row=next(r for r in rows if r['id']==int(post['data']['id']))
                    settings=json.loads(row['settings']);assert len(settings['clients'])==2,'second client did not persist'
                    added=json.loads(post['data']['settings'])['clients'][0]
                    saved=next(c for c in settings['clients'] if c['email']==added['email'])
                    for key,value in added.items():
                        if key not in ('created_at','updated_at'): assert saved.get(key)==value, 'saved client field differs: '+key
                    if row['protocol']=='shadowtls':
                        assert any(c['email']==added['email'] for c in settings['inner']['settings']['clients']), 'new inner account binding missing'
                for row in rows:
                    settings=json.loads(row['settings'])
                    for client in settings['clients']:
                        assert isinstance(client.get('tgId',0),int),'non-numeric Telegram ID persisted'
                        config=panel.export(client['subId']);filename=folder/f'export-{index}-{row["id"]}-{client["subId"]}.json';filename.write_text(json.dumps(config))
                        completed=subprocess.run([str(args.core.resolve()),'run','-test','-config',str(filename)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
                        (filename.with_suffix('.log')).write_text(completed.stdout)
                        assert completed.returncode==0, 'exported config rejected by real core: '+completed.stdout[-800:]
                record(name+f'.persist-export-core{index+1}',True,f'{len(rows)} saved inbound(s)')
            panel.restart();record(name+'.real-core-restart',True)
        except Exception as error:
            record(name,False,str(error))
        finally:
            h.stop(panel.p);time.sleep(.15)
finally:
    for process in reversed(h.PROCESSES):h.stop(process)
    namespace=os.readlink('/proc/self/ns/net')
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
        try:
            if os.readlink(proc/'ns/net')==namespace:os.kill(int(proc.name),15)
        except (FileNotFoundError,ProcessLookupError,PermissionError):pass
    report={'passed':sum(r['ok'] for r in results),'failed':sum(not r['ok'] for r in results),'groups':len(groups),'panel':str(args.panel),'core':str(args.core),'captured':str(args.captured),'bodyRepair':False,'results':results}
    (args.work/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('RESULTS '+str(args.work/'results.json'),flush=True)
raise SystemExit(1 if any(not r['ok'] for r in results) else 0)
