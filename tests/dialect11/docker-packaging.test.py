#!/usr/bin/env python3
"""Exercise Docker packaging with synthetic inputs and mocked compiler/network.

Run: python3 tests/dialect11/docker-packaging.test.py
By default no real Go compile, image build, network request, or service change
is performed. Set D11_DOCKER_CONTEXT_TEST=1 to additionally check .dockerignore
with a tiny FROM-scratch build/export; it runs no Go compiler or application.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GEO = ('geoip.dat', 'geosite.dat', 'geoip_IR.dat', 'geosite_IR.dat', 'geoip_RU.dat', 'geosite_RU.dat')
MOCK_GO = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'tool': 'go', 'args': args, 'cwd': os.getcwd(),
                       'cgo': os.environ.get('CGO_ENABLED'), 'arch': os.environ.get('GOARCH'),
                       'goos': os.environ.get('GOOS'), 'gomaxprocs': os.environ.get('GOMAXPROCS')}) + '\n')
if args == ['env', 'GOHOSTARCH']:
    print(os.environ.get('FAKE_HOST_ARCH', 'amd64'))
    raise SystemExit(0)
if not args or args[0] != 'build':
    raise SystemExit('unexpected go command')
output = pathlib.Path(args[args.index('-o') + 1])
kind = 'panel' if output.name == 'x-ui' else 'core'
if os.environ.get('FAKE_GO_FAIL') == kind:
    raise SystemExit(7)
code = """import json, os, sys
kind = %r
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'tool': kind, 'args': sys.argv[1:], 'asset': os.environ.get('XRAY_LOCATION_ASSET')}) + '\\n')
if kind == 'core':
    raise SystemExit(int(os.environ.get('FAKE_CORE_EXIT', '0')))
raise SystemExit(int(os.environ.get('FAKE_PANEL_EXIT', '0')))
""" % kind
output.write_text('#!' + sys.executable + '\n' + code)
output.chmod(0o755)
'''
MOCK_CURL = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'tool': 'curl', 'args': args}) + '\n')
output = pathlib.Path(args[args.index('--output') + 1])
if os.environ.get('FAKE_CURL_FAIL') in ('all', output.name):
    raise SystemExit(22)
output.write_bytes(b'' if os.environ.get('FAKE_CURL_EMPTY') == output.name else b'synthetic-geo')
'''


class DockerPackaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dialect11-docker-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source tree'
        self.root.mkdir()
        self.mock = Path(self.temp.name) / 'tools'
        self.mock.mkdir()
        self.log = Path(self.temp.name) / 'calls.jsonl'
        shutil.copy2(ROOT / 'DockerInit.sh', self.root / 'DockerInit.sh')
        for name, value in {
            'go.mod': 'module synthetic\ngo 1.27\n',
            'main.go': 'package main\nfunc main(){newRestoreSignalGate()}\n',
            'restore_signal_gate.go': 'package main\nfunc newRestoreSignalGate(){}\n',
            'core/main/main.go': 'package main\nfunc main(){}\n',
            'core/LICENSE': 'core license', 'LICENSE': 'panel license',
            'core/licenses/dependency.txt': 'dependency license',
            'DIALECT11.md': 'native protocol guide',
            'web/service/config.json': '{"inbounds":[]}',
            'build/previous-success': 'keep if validation fails',
        }.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(value)
        for name, code in [('go', MOCK_GO), ('curl', MOCK_CURL)]:
            p = self.mock / name
            p.write_text('#!' + sys.executable + '\n' + code)
            p.chmod(0o755)
        self.env = os.environ.copy()
        for key in ('GEO_SRC', 'GO_BUILD_PARALLELISM', 'GOMAXPROCS', 'GOFLAGS', 'CGO_ENABLED', 'GOARCH'):
            self.env.pop(key, None)
        self.env.update(PATH=str(self.mock) + os.pathsep + os.defpath, FAKE_LOG=str(self.log), FAKE_HOST_ARCH='amd64')

    def invoke(self, arch='amd64', **env):
        self.env.update({k: str(v) for k, v in env.items()})
        args = ['sh', str(self.root / 'DockerInit.sh')]
        if arch is not None:
            args.append(arch)
        return subprocess.run(args, env=self.env, cwd=self.temp.name, text=True, capture_output=True, timeout=15)

    def calls(self, tool=None):
        calls = [json.loads(s) for s in self.log.read_text().splitlines()] if self.log.exists() else []
        return [c for c in calls if tool is None or c['tool'] == tool]

    def assert_clean_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'build/previous-success').exists())
        self.assertFalse(list(self.root.glob('.docker-build-stage.*')))

    def test_amd64_builds_whole_panel_and_local_native_core(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [c for c in self.calls('go') if c['args'][0] == 'build']
        self.assertEqual(len(builds), 2)
        for call, package, cgo, cwd in zip(builds, ['.', './main'], ['1', '0'], [self.root, self.root / 'core']):
            self.assertEqual(call['args'][-1], package)
            self.assertEqual(call['cgo'], cgo)
            self.assertEqual(call['arch'], 'amd64')
            self.assertEqual(call['goos'], 'linux')
            self.assertEqual(call['gomaxprocs'], '2')
            self.assertEqual(call['cwd'], str(cwd))
            self.assertEqual(call['args'][call['args'].index('-p') + 1], '2')
        expected = ['x-ui', 'bin/xray-linux-amd64', 'licenses/PANEL-LICENSE',
                    'licenses/core/XRAY-LICENSE', 'licenses/core/dependency.txt', 'DIALECT11.md']
        for name in expected + ['bin/' + n for n in GEO]:
            self.assertTrue((self.root / 'build' / name).is_file(), name)
        self.assertFalse((self.root / 'build/previous-success').exists())
        self.assertFalse(list(self.root.glob('.docker-build-stage.*')))
        self.assertEqual(len(self.calls('curl')), 6)
        for call in self.calls('curl'):
            self.assertNotIn('XTLS/Xray-core', call['args'][-1])
            self.assertTrue(call['args'][-1].endswith('.dat'))
        core = self.calls('core')
        self.assertEqual(len(core), 1)
        self.assertEqual(core[0]['args'], ['run', '-test', '-c', str(self.root / 'web/service/config.json')])
        self.assertTrue(core[0]['asset'].endswith('/bin'))
        self.assertEqual(self.calls('panel')[0]['args'], ['-v'])

    def test_arm64_uses_target_platform_compiler(self):
        result = self.invoke('arm64', FAKE_HOST_ARCH='arm64', GO_BUILD_PARALLELISM='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'build/bin/xray-linux-arm64').is_file())
        self.assertFalse((self.root / 'build/bin/xray-linux-amd64').exists())
        builds = [c for c in self.calls('go') if c['args'][0] == 'build']
        self.assertTrue(all(c['arch'] == 'arm64' and c['args'][c['args'].index('-p') + 1] == '1' for c in builds))

    def test_unknown_or_missing_architecture_fails_without_tools(self):
        for arch in [None, '', '386', 'aarch64', 'armv7', '../amd64']:
            with self.subTest(arch=arch):
                self.assert_clean_failure(self.invoke(arch))
        self.assertEqual(self.calls(), [])

    def test_cgo_cross_platform_mismatch_is_explicit(self):
        self.assert_clean_failure(self.invoke('arm64'))
        self.assertFalse([c for c in self.calls('go') if c['args'][0] == 'build'])

    def test_invalid_parallelism_fails(self):
        self.assert_clean_failure(self.invoke(GO_BUILD_PARALLELISM='99'))
        self.assertFalse([c for c in self.calls('go') if c['args'][0] == 'build'])

    def local_geo(self):
        geo = Path(self.temp.name) / 'local geo'
        geo.mkdir()
        for name in GEO:
            (geo / name).write_text('local-' + name)
        return geo

    def test_complete_local_geo_avoids_network(self):
        geo = self.local_geo()
        result = self.invoke(GEO_SRC=geo, FAKE_CURL_FAIL='all')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls('curl'), [])
        self.assertEqual((self.root / 'build/bin/geosite_IR.dat').read_text(), 'local-geosite_IR.dat')

    def test_missing_local_geo_fails_without_download_fallback(self):
        geo = self.local_geo()
        (geo / 'geosite_IR.dat').unlink()
        self.assert_clean_failure(self.invoke(GEO_SRC=geo))
        self.assertEqual(self.calls('curl'), [])
        self.assertEqual(self.calls('core'), [])

    def test_download_failure_preserves_previous_bundle(self):
        self.assert_clean_failure(self.invoke(FAKE_CURL_FAIL='geosite.dat'))
        self.assertEqual(self.calls('core'), [])

    def test_empty_geo_download_is_rejected(self):
        self.assert_clean_failure(self.invoke(FAKE_CURL_EMPTY='geoip.dat'))
        self.assertEqual(self.calls('core'), [])

    def test_core_template_failure_preserves_previous_bundle(self):
        self.assert_clean_failure(self.invoke(FAKE_CORE_EXIT='3'))
        self.assertEqual(len(self.calls('core')), 1)
        self.assertEqual(self.calls('panel'), [])

    def test_panel_runtime_failure_preserves_previous_bundle(self):
        self.assert_clean_failure(self.invoke(FAKE_PANEL_EXIT='3'))
        self.assertEqual(len(self.calls('panel')), 1)

    def test_compile_failure_preserves_previous_bundle(self):
        self.assert_clean_failure(self.invoke(FAKE_GO_FAIL='core'))
        self.assertEqual(self.calls('curl'), [])

    def test_missing_notice_fails_instead_of_shipping_incomplete_bundle(self):
        (self.root / 'core/LICENSE').unlink()
        self.assert_clean_failure(self.invoke())

    def test_dockerfile_uses_same_alpine_release_and_build_helper(self):
        text = (ROOT / 'Dockerfile').read_text()
        self.assertIn('ARG ALPINE_VERSION=3.24', text)
        self.assertIn('FROM golang:1.27-alpine${ALPINE_VERSION} AS builder', text)
        self.assertIn('FROM alpine:${ALPINE_VERSION}', text)
        self.assertIn('RUN ./DockerInit.sh "$TARGETARCH"', text)
        self.assertIn('ENV GOTOOLCHAIN=local', text)
        self.assertNotIn('go build -ldflags "-w -s" -o build/x-ui main.go', text)
        self.assertIn('COPY --from=builder /app/build/ /app/', text)

    def test_dockerignore_keeps_source_tests_and_excludes_runtime_material(self):
        patterns = (ROOT / '.dockerignore').read_text().splitlines()
        for pattern in ['/build', '/dist', '/bin', '**/node_modules', '**/__pycache__',
                        '**/.env', '**/*.db', '**/*.pem', '**/*.key', '/cert', '/certs',
                        '/windows_files/SSL/*.exe', '!**/testdata/**']:
            self.assertIn(pattern, patterns)
        self.assertNotIn('tests', patterns)
        self.assertNotIn('**/*_test.go', patterns)
        self.assertNotIn('**/*.go', patterns)

    @unittest.skipUnless(os.environ.get('D11_DOCKER_CONTEXT_TEST') == '1',
                         'set D11_DOCKER_CONTEXT_TEST=1 for the optional Docker context check')
    def test_dockerignore_actual_build_context(self):
        context = Path(self.temp.name) / 'docker context'
        output = Path(self.temp.name) / 'exported context'
        context.mkdir()
        shutil.copy2(ROOT / '.dockerignore', context / '.dockerignore')
        (context / 'Dockerfile').write_text('FROM scratch\nCOPY . /context/\n')
        kept = ['main.go', 'restore_signal_gate.go', 'core/main/main.go',
                'tests/example_test.go', 'core/proxy/example/testdata/fixture.pem',
                'core/proxy/example/testdata/vector.json', '.env.example']
        excluded = ['.git/config', 'build/x-ui', 'dist/release.tar.gz', 'bin/xray-linux-amd64',
                    'node_modules/example/index.js', 'cache/__pycache__/compiled.pyc',
                    'runtime.db', 'runtime.db-wal', 'nested/live.db', '.env', '.env.local',
                    'nested/.env', 'server.pem', 'server.key', 'cert/private.crt',
                    'certs/private.pem', 'secrets/api-token', 'windows_files/SSL/setup.exe']
        for name in kept + excluded:
            p = context / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('synthetic fixture; not a real credential')
        result = subprocess.run(['docker', 'buildx', 'build', '--progress=plain',
                                 '--network=none', '--output', 'type=local,dest=' + str(output),
                                 str(context)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in kept:
            self.assertTrue((output / 'context' / name).is_file(), name + ' excluded incorrectly')
        for name in excluded:
            self.assertFalse((output / 'context' / name).exists(), name + ' leaked into Docker context')


if __name__ == '__main__':
    unittest.main(verbosity=2)
