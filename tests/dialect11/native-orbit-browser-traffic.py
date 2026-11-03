#!/usr/bin/env python3
"""One real Orbit WS traffic check using an exact captured browser Create body."""
import argparse, importlib.util, json, os, pathlib, subprocess, sys
sys.dont_write_bytecode=True
os.environ['PYTHONDONTWRITEBYTECODE']='1'
HERE=pathlib.Path(__file__).resolve().parent
if '--netns' in sys.argv:
    os.environ['D11_HOST_NETNS']=os.readlink('/proc/self/ns/net')
    os.execvp('unshare',['unshare','--net','python3',str(pathlib.Path(__file__).resolve()),*[a for a in sys.argv[1:] if a!='--netns']])
assert os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['D11_HOST_NETNS']
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','address','add','198.18.0.1/32','dev','lo'],check=True)
spec=importlib.util.spec_from_file_location('panel_e2e',HERE/'panel-e2e.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
p=argparse.ArgumentParser();p.add_argument('--panel',type=pathlib.Path,required=True);p.add_argument('--core',type=pathlib.Path,required=True);p.add_argument('--client-core',type=pathlib.Path,required=True);p.add_argument('--captured',type=pathlib.Path,required=True);p.add_argument('--work',type=pathlib.Path,required=True);args=p.parse_args()
assert not args.work.exists();args.work.mkdir(mode=0o700,parents=True)
posts=[x for x in json.loads(args.captured.read_text()) if x['case']=='optional-orbit-websocket-roundtrip-core-valid' and x['path'].endswith('/add')]
assert len(posts)==1,'need exact browser WS create request'
post=posts[0];settings=json.loads(post['data']['settings']);results=[];panel=None;targets=[];udp=None
try:
    h.certificates(args.work/'targets');targets,udp=h.start_targets(args.work/'targets')
    panel=h.Panel(args.work/'panel',args.panel.resolve(),args.core.resolve());panel.init();panel.start()
    row=panel.api('POST',post['path'].removeprefix('/review'),data=post['rawBody'],headers={'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8','X-Requested-With':'XMLHttpRequest'})
    saved=panel.api('GET','/panel/api/inbounds/get/'+str(row['id']))
    assert json.loads(saved['settings'])['host']==settings['host']
    h.result('exact-browser-ws-save',True)
    panel.restart();assert h.wait_port(int(post['data']['port']),10),'saved WS listener did not start'
    exported=panel.export(settings['clients'][0]['subId']);(args.work/'export.json').write_text(json.dumps(exported))
    outbound=next(o for o in exported['outbounds'] if o['tag']=='proxy')['settings']
    assert outbound['host']==settings['host'];assert outbound.get('peer')==settings['clientExport']['serverName']
    h.result('exact-browser-ws-export-peer',True)
    h.traffic_client(args.client_core.resolve(),exported,{'name':'browser-generated-orbit-ws','large':True,'udp':True},args.work/'traffic','final')
    assert all(r['ok'] for r in h.RESULTS),'traffic failure'
except Exception as error:
    h.result('browser-ws-completion',False,str(error))
finally:
    if panel:h.stop(panel.p)
    for process in reversed(h.PROCESSES):h.stop(process)
    for target in targets:target.shutdown()
    if udp:udp.close()
    namespace=os.readlink('/proc/self/ns/net')
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
        try:
            if os.readlink(proc/'ns/net')==namespace:os.kill(int(proc.name),15)
        except (FileNotFoundError,ProcessLookupError,PermissionError):pass
    report={'passed':sum(r['ok'] for r in h.RESULTS),'failed':sum(not r['ok'] for r in h.RESULTS),'bodyRepair':False,'currentClient':str(args.client_core),'panel':str(args.panel),'core':str(args.core),'captured':str(args.captured),'results':h.RESULTS}
    (args.work/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('RESULTS '+str(args.work/'results.json'),flush=True)
raise SystemExit(1 if any(not r['ok'] for r in h.RESULTS) else 0)
