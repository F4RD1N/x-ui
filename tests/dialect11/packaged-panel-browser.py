#!/usr/bin/env python3
"""Actual embedded package UI smoke in a disposable panel and private netns."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

p=argparse.ArgumentParser(description=__doc__)
for name in ('panel','core','client-core','work'):
 p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2],help='source checkout containing tests/dialect11/panel-e2e.py; defaults to this checkout')
p.add_argument('--netns',action='store_true')
a=p.parse_args()
if a.netns:
 os.environ['D11_HOST_NETNS']=os.readlink('/proc/self/ns/net')
 os.execvp('unshare',['unshare','--net',sys.executable,'-B',str(Path(__file__).resolve()),*[x for x in sys.argv[1:] if x!='--netns']])
assert os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['D11_HOST_NETNS'],'private netns required'
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','address','add','198.18.0.1/32','dev','lo'],check=True)
os.umask(0o077)
a.work=a.work.resolve();assert not a.work.exists(),'fresh work directory required';a.work.mkdir(parents=True,mode=0o700)
spec=importlib.util.spec_from_file_location('panel_e2e',a.repo/'tests/dialect11/panel-e2e.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
report={'passed':False,'network':'private netns; loopback only','sourceTemplatesUsed':False,'binaries':{name:{'path':str(path.resolve()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in [('panel',a.panel),('core',a.core),('client',a.client_core)]}}
panel=None
try:
 panel=h.Panel(a.work/'panel',a.panel.resolve(),a.core.resolve());panel.init();panel.start()
 cases=[]
 for i,protocol in enumerate(['openvpn','anytls','shadowtls','dnstt','mieru']):
  request={'kind':'inbound-profile','protocol':protocol,'email':'embedded-'+protocol+'@example.test'}
  if protocol=='anytls':request['serverName']='127.0.0.1'
  if protocol=='dnstt':request['domain']='embedded.example.test'
  if protocol=='shadowtls':request['handshakeAddress']='127.0.0.1'
  profile=panel.api('POST','/panel/api/server/native/credentials',json=request)
  # Unknown-field preservation belongs in panel metadata. OpenVPN correctly
  # rejects unknown runtime settings with its strict core decoder.
  settings=profile['settings'];settings.setdefault('clientExport',{})['futurePanelMarker']={'preserved':protocol}
  settings['clients'][0]['comment']='embedded UI preservation marker'
  port=31100+i
  case={'name':'embedded-'+protocol,'protocol':protocol,'port':port,'settings':settings,'stream':profile.get('streamSettings') or {}}
  obj=panel.api('POST','/panel/api/inbounds/add',json=h.payload(case))
  row=panel.api('GET','/panel/api/inbounds/get/'+str(obj['id']))
  cases.append({'id':row['id'],'protocol':protocol,'port':port,'remark':row['remark'],'email':json.loads(row['settings'])['clients'][0]['email']})
 panel.restart()
 session={'url':panel.url,'cookies':[{'name':cookie.name,'value':cookie.value,'url':'http://127.0.0.1:28000','path':'/'} for cookie in panel.http.cookies],'cases':cases}
 # Playwright accepts either url or domain+path, not both.
 for cookie in session['cookies']:cookie.pop('path',None)
 h.write_json(a.work/'session.json',session)
 node=Path(__file__).with_name('packaged-panel-browser.js')
 result=subprocess.run(['node',str(node),str(a.work/'session.json'),str(a.work)],cwd=a.repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (a.work/'browser.log').write_text(result.stdout)
 assert result.returncode==0,'embedded browser failed; see browser.log and browser-results.json'
 browser_report=json.loads((a.work/'browser-results.json').read_text())
 assert browser_report['passed'],'embedded browser reported failure'
 for case in cases:
  row=panel.api('GET','/panel/api/inbounds/get/'+str(case['id']))
  settings=json.loads(row['settings'])
  assert settings.get('clientExport',{}).get('futurePanelMarker')=={'preserved':case['protocol']},'unknown panel metadata lost during UI edit'
  assert settings['clients'][0]['comment']=='embedded UI preservation marker','client metadata lost during UI edit'
  assert (settings['limits']['handshakeSeconds'] if case['protocol']=='openvpn' else settings['handshakeTimeout'])==19,'typed timeout edit was not persisted'
  path=a.work/('copied-'+case['protocol']+'.json')
  check=subprocess.run([str(a.client_core.resolve()),'run','-test','-c',str(path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30,env=dict(os.environ,**{'xray.endpoint.mapping':'off'}))
  path.with_suffix('.parse.log').write_text(check.stdout)
  assert check.returncode==0,'copied full JSON rejected by immutable client: '+case['protocol']
 report.update(passed=True,protocols=[c['protocol'] for c in cases],copiedConfigsParsed=len(cases),browserChecks=len(browser_report['checks']),consoleErrors=browser_report['consoleErrors'],pageErrors=browser_report['pageErrors'])
except Exception as exc:
 report['error']=str(exc);(a.work/'failure.txt').write_text(traceback.format_exc())
finally:
 for process in reversed(h.PROCESSES):h.stop(process)
 (a.work/'results.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'passed':report['passed'],'report':str(a.work/'results.json')}))
raise SystemExit(0 if report['passed'] else 1)
