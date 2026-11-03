#!/usr/bin/env python3
"""Exercise the complete CLI dispatcher with inert local network/installer fakes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).resolve().parents[2] / 'x-ui.sh'
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args=sys.argv[1:]; root=Path(os.environ['CLI_TEST_ROOT']); scenario=os.environ['CLI_TEST_SCENARIO']
with (root/'curl-calls.jsonl').open('a') as f: f.write(json.dumps(args)+'\n')
if any('api.github.com' in a for a in args):
    if scenario=='api_failure': sys.exit(22)
    tag='v2.9.0-dialect.11.6'
    if scenario=='bad_tag': tag='../../unexpected'
    data=json.dumps({'tag_name':tag,'padding':['x'*16384]*128},indent=2).encode()
    if scenario=='empty_release': data=b'{}'
    try:
        for i in range(0,len(data),4096): os.write(1,data[i:i+4096])
    except BrokenPipeError:
        print('curl: (23) Failure writing output to destination',file=sys.stderr);sys.exit(23)
    (root/'release-fully-consumed').touch();sys.exit(0)
if any('raw.githubusercontent.com' in a for a in args):
    if scenario=='installer_download_failure': sys.exit(28)
    dest=Path(args[args.index('-o')+1])
    script='printf "%s\\n" "$XUI_MODE" "$@" > "$CLI_TEST_ROOT/installed"\nexit "${CLI_TEST_INSTALL_RC:-0}"\n'
    if scenario=='installer_syntax':script='if then\n'
    dest.write_text(script);sys.exit(0)
sys.exit(91)
'''

def executable(path, text):
    path.write_text(text)
    path.chmod(0o700)


def run_case(name, args, stdin='', scenario='ok', current='2.9.0-dialect.10', rc=0, install=True, installer_rc=0):
    with tempfile.TemporaryDirectory(prefix='xui-cli-update-') as folder:
        root=Path(folder);bin_dir=root/'fake-bin';bin_dir.mkdir()
        main=root/'panel with spaces';main.mkdir();units=root/'units';units.mkdir();(units/'x-ui.service').touch()
        temporary=root/'temporary';temporary.mkdir()
        executable(main/'x-ui','#!/bin/bash\nprintf "%s\\n" "$CLI_TEST_CURRENT"\n')
        executable(bin_dir/'systemctl','#!/bin/bash\necho "Active: active (running)"\n')
        executable(bin_dir/'curl',FAKE_CURL)
        env={**os.environ,'PATH':str(bin_dir)+os.pathsep+os.environ['PATH'],'XUI_MAIN_FOLDER':str(main),'XUI_SERVICE':str(units),'XUI_LOG_FOLDER':str(root/'logs'),'TMPDIR':str(temporary),'CLI_TEST_ROOT':str(root),'CLI_TEST_SCENARIO':scenario,'CLI_TEST_CURRENT':current,'CLI_TEST_INSTALL_RC':str(installer_rc)}
        result=subprocess.run(['bash',str(SCRIPT),'update',*args],input=stdin,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=15)
        assert result.returncode==rc,(name,result.returncode,result.stdout,result.stderr)
        assert (root/'installed').exists()==install,(name,result.stdout,result.stderr)
        if install:
            assert (root/'installed').read_text().splitlines()==['update','update','tag=v2.9.0-dialect.11.6'],name
            assert (root/'release-fully-consumed').exists(),name
            calls=[json.loads(line) for line in (root/'curl-calls.jsonl').read_text().splitlines()]
            assert len(calls)==2 and all('--max-time' in c for c in calls),name
        assert not list(temporary.iterdir()),(name,'installer temporary file leaked')
        assert 'curl: (23)' not in result.stderr,(name,'early-closing release lookup')
        if args and args[0] in ('-y','--yes'):
            assert 'Default y' not in result.stdout+result.stderr and 'Default n' not in result.stdout+result.stderr,name
        print('PASS '+name,flush=True)


def main():
    if os.geteuid()!=0:
        raise SystemExit('Full CLI tests require root because the production script requires root; all mutation paths are redirected to temporary files.')
    run_case('short yes flag bypasses negative stdin',['-y'],'n\n')
    run_case('long yes flag bypasses negative stdin',['--yes'],'n\n')
    run_case('interactive acceptance pins checked tag',[],'y\n')
    run_case('interactive decline starts no installer',[],'n\n',install=False)
    run_case('same-version default declines reinstall',[],'\n',current='2.9.0-dialect.11.6',install=False)
    run_case('explicit yes permits same-version reinstall',['-y'],'n\n',current='2.9.0-dialect.11.6')
    run_case('unknown option is rejected',['--unknown'],rc=2,install=False)
    run_case('API failure starts no installer',['-y'],scenario='api_failure',rc=1,install=False)
    run_case('unsafe tag is rejected',['-y'],scenario='bad_tag',rc=1,install=False)
    run_case('missing tag is rejected',['-y'],scenario='empty_release',rc=1,install=False)
    run_case('installer download failure propagates',['-y'],scenario='installer_download_failure',rc=1,install=False)
    run_case('invalid installer syntax is not run',['-y'],scenario='installer_syntax',rc=1,install=False)
    run_case('installer exit status reaches caller',['-y'],rc=7,installer_rc=7)
    print('RESULT: 13 passed, 0 failed')

if __name__=='__main__':main()
