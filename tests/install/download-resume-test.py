#!/usr/bin/env python3
"""Exercise only installer download helpers against a loopback HTTP fixture.

No installer entry point, service manager, public network or installed files are
touched. The wrapper executes real curl; it redirects release URLs to the local
fixture and shortens the low-speed timer only for the idle-transfer test.
"""

import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
REAL_CURL = shutil.which("curl")
TAG = "v-local-download-test"
ASSET = "x-ui-linux-amd64.tar.gz"


def archive_bytes():
    """Deterministic incompressible payload makes interrupted bytes meaningful."""
    content = random.Random(91826).randbytes(256 * 1024)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        entry = tarfile.TarInfo("x-ui/payload")
        entry.size = len(content)
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(content))
    return stream.getvalue()


PAYLOAD = archive_bytes()
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Fixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, behavior, payload=PAYLOAD):
        super().__init__(("127.0.0.1", 0), Handler)
        self.behavior = behavior
        self.payload = payload
        self.requests = []
        self.mutex = threading.Lock()
        self.checksums = f"{hashlib.sha256(payload).hexdigest()}  {ASSET}\n".encode()
        self.checksum_status = 200


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # curl deliberately closes rejected status/range responses.
            pass

    def body(self, status, body, headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        with self.server.mutex:
            request = {"path": self.path, "range": self.headers.get("Range", "")}
            self.server.requests.append(request)
            artifact_index = sum(
                item["path"].endswith((ASSET, "/artifact"))
                for item in self.server.requests
            )
        if self.path.endswith("/releases/latest"):
            # The tag arrives before considerably more than a pipe buffer of
            # data. grep -m1 closes early and reproduces curl error 23 here.
            self.body(200, json.dumps({"tag_name": TAG, "body": "x" * 2097152}).encode())
            return
        if self.path.endswith("/SHA256SUMS"):
            self.body(self.server.checksum_status, self.server.checksums)
            return
        if not self.path.endswith((ASSET, "/artifact")):
            self.body(404, b"unexpected fixture path")
            return
        behavior = self.server.behavior
        data = self.server.payload
        offset = 0
        if request["range"]:
            offset = int(request["range"].removeprefix("bytes=").split("-")[0])
        if behavior == "errors":
            self.body(503, b"temporary failure")
            return
        if behavior == "not_found":
            self.body(404, b"missing")
            return
        if offset >= len(data) or (behavior == "truncated416" and artifact_index == 1):
            self.body(416, b"", {"Content-Range": f"bytes */{len(data)}"})
            return
        if behavior == "ignore_range":
            offset = 0
        status = 206 if offset else 200
        if behavior == "wrong_range" and offset:
            # The data and declared range both start at the wrong offset.
            offset += 7
        response = data[offset:]
        self.send_response(status)
        self.send_header("Content-Length", str(len(response)))
        if status == 206:
            self.send_header("Content-Range", f"bytes {offset}-{len(data) - 1}/{len(data)}")
        self.end_headers()
        try:
            if behavior in ("interrupted", "stalled") and artifact_index == 1:
                self.wfile.write(response[:65536])
                self.wfile.flush()
                if behavior == "stalled":
                    # curl's rolling speed average itself covers several
                    # seconds, in addition to the shortened idle timer.
                    time.sleep(15)
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            if behavior == "throttled":
                for start in range(0, len(response), 4096):
                    self.wfile.write(response[start : start + 4096])
                    self.wfile.flush()
                    time.sleep(0.055)
            else:
                self.wfile.write(response)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="x-ui-download-test-")
        self.directory = Path(self.temp.name)
        self.dest = self.directory / "download.tar.gz"
        self.fixture = None
        source = (ROOT / "install.sh").read_text()
        begin = source.index("# ---- fetch ")
        end = source.index("# ---- install ", begin)
        self.helpers = self.directory / "fetch-functions.sh"
        self.helpers.write_text(source[begin:end])
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        wrapper = self.bin / "curl"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,sys\n"
            "from urllib.parse import urlsplit\n"
            "args=sys.argv[1:]\n"
            "with open(os.environ['TEST_CURL_LOG'],'a') as out: out.write(json.dumps(args)+'\\n')\n"
            "for i,arg in enumerate(args):\n"
            "    if arg.startswith(('http://','https://')):\n"
            "        parsed=urlsplit(arg)\n"
            "        if parsed.hostname in ('github.com','api.github.com'):\n"
            "            args[i]=os.environ['TEST_HTTP_BASE']+parsed.path\n"
            "        elif parsed.hostname!='127.0.0.1':\n"
            "            raise SystemExit('external network forbidden by download test')\n"
            "    if os.environ.get('TEST_SHORT_IDLE')=='1' and arg=='--speed-time': args[i+1]='2'\n"
            "os.execv(os.environ['TEST_REAL_CURL'],[os.environ['TEST_REAL_CURL']]+args)\n"
        )
        wrapper.chmod(0o755)

    def tearDown(self):
        if self.fixture:
            self.fixture.shutdown()
            self.fixture.server_close()
        self.temp.cleanup()

    def start(self, behavior="normal", payload=PAYLOAD):
        self.fixture = Fixture(behavior, payload)
        threading.Thread(target=self.fixture.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.fixture.server_port}"

    def run_shell(self, invocation, short_idle=False):
        environment = os.environ.copy()
        environment.update(
            PATH=f"{self.bin}:{environment['PATH']}",
            TEST_REAL_CURL=REAL_CURL,
            TEST_CURL_LOG=str(self.directory / "curl.jsonl"),
            TEST_HTTP_BASE=f"http://127.0.0.1:{self.fixture.server_port}",
            TEST_SHORT_IDLE="1" if short_idle else "0",
            XUI_LOCAL_TARBALL="",
            XUI_TAG=TAG,
            XUI_REPO="fixture/repo",
            ARCH="amd64",
            NO_PROXY="127.0.0.1",
            no_proxy="127.0.0.1",
        )
        script = (
            "set -uo pipefail\n"
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            "info() { printf '%s\\n' \"$*\"; }\n"
            "warn() { printf '%s\\n' \"$*\" >&2; }\n"
            "sleep() { :; }\n"
            f"source {shlex.quote(str(self.helpers))}\n"
            f"{invocation}\n"
        )
        return subprocess.run(
            ["bash", "-c", script],
            cwd=self.directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=35,
        )

    def download(self, digest=DIGEST, short_idle=False):
        url = f"http://127.0.0.1:{self.fixture.server_port}/artifact"
        return self.run_shell(
            "download_tarball "
            + " ".join(shlex.quote(value) for value in (url, str(self.dest), digest)),
            short_idle=short_idle,
        )

    def artifacts(self):
        return [item for item in self.fixture.requests if item["path"].endswith((ASSET, "/artifact"))]

    def assert_valid(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.dest.read_bytes(), self.fixture.payload)

    def test_fresh_download(self):
        self.start()
        self.assert_valid(self.download())
        self.assertEqual(len(self.artifacts()), 1)

    def test_interrupted_download_resumes_existing_bytes(self):
        self.start("interrupted")
        self.assert_valid(self.download())
        self.assertEqual([item["range"] for item in self.artifacts()], ["", "bytes=65536-"])

    def test_productive_slow_download_has_no_short_total_cap(self):
        self.start("throttled")
        before = time.monotonic()
        self.assert_valid(self.download())
        self.assertGreater(time.monotonic() - before, 3)
        self.assertEqual(len(self.artifacts()), 1)
        commands = [json.loads(line) for line in (self.directory / "curl.jsonl").read_text().splitlines()]
        for command in commands:
            self.assertNotIn("--max-time", command, "productive artifact transfers must not hit the old 900s limit")
            self.assertIn("--speed-limit", command)
            self.assertIn("--speed-time", command)
            self.assertIn("--connect-timeout", command)

    def test_server_ignores_range_restarts_cleanly(self):
        self.start("ignore_range")
        self.dest.write_bytes(PAYLOAD[:65536])
        self.assert_valid(self.download())
        self.assertEqual([item["range"] for item in self.artifacts()], ["bytes=65536-", ""])

    def test_complete_file_and_http416(self):
        self.start()
        self.dest.write_bytes(PAYLOAD)
        self.assert_valid(self.download())
        requests = self.artifacts()
        if requests:  # A verified-complete preflight is also safe.
            self.assertEqual([item["range"] for item in requests], [f"bytes={len(PAYLOAD)}-"])

    def test_truncated_file_http416_restarts_cleanly(self):
        self.start("truncated416")
        self.dest.write_bytes(PAYLOAD[:65536])
        self.assert_valid(self.download())
        self.assertEqual([item["range"] for item in self.artifacts()], ["bytes=65536-", ""])

    def test_wrong206_offset_cannot_be_accepted(self):
        self.start("wrong_range")
        self.dest.write_bytes(PAYLOAD[:65536])
        result = self.download()
        self.assertEqual(self.artifacts()[0]["range"], "bytes=65536-")
        if result.returncode == 0:
            self.assert_valid(result)
            self.assertTrue(any(item["range"] == "" for item in self.artifacts()[1:]))
        self.assertLessEqual(len(self.artifacts()), 5)

    def test_checksum_mismatch_is_rejected(self):
        self.start()
        result = self.download("0" * 64)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.directory / "x-ui").exists())

    def test_matching_checksum_does_not_accept_invalid_archive(self):
        payload = b"not a gzip tar archive\n"
        self.start(payload=payload)
        result = self.download(hashlib.sha256(payload).hexdigest())
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.directory / "x-ui").exists())

    def test_valid_gzip_with_matching_checksum_must_contain_tar(self):
        payload = gzip.compress(b"not a tar archive\n")
        self.start(payload=payload)
        result = self.download(hashlib.sha256(payload).hexdigest())
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.directory / "x-ui").exists())

    def test_retry_count_is_bounded(self):
        self.start("errors")
        result = self.download()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertGreaterEqual(len(self.artifacts()), 2)
        self.assertLessEqual(len(self.artifacts()), 5)

    def test_stalled_transfer_resumes_after_idle_timeout(self):
        self.start("stalled")
        result = self.download(short_idle=True)
        self.assert_valid(result)
        self.assertIn("curl: (28)", result.stderr)
        self.assertEqual([item["range"] for item in self.artifacts()], ["", "bytes=65536-"])

    def test_checksum_document_rejects_duplicate_asset(self):
        self.start()
        self.fixture.checksums *= 2
        result = self.run_shell(f"fetch_tarball {shlex.quote(str(self.dest))}")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.artifacts(), [])

    def test_checksum_document_rejects_missing_asset(self):
        self.start()
        self.fixture.checksums = f"{DIGEST}  other-archive.tar.gz\n".encode()
        result = self.run_shell(f"fetch_tarball {shlex.quote(str(self.dest))}")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.artifacts(), [])

    def test_checksum_document_rejects_nonhex_digest(self):
        self.start()
        self.fixture.checksums = f"{'z' * 64}  {ASSET}\n".encode()
        result = self.run_shell(f"fetch_tarball {shlex.quote(str(self.dest))}")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.artifacts(), [])

    def test_checksum_document_accepts_binary_marker_and_uppercase(self):
        self.start()
        self.fixture.checksums = f"{DIGEST.upper()} *{ASSET}\n".encode()
        self.assert_valid(self.run_shell(f"fetch_tarball {shlex.quote(str(self.dest))}"))

    def test_checksumless_explicit_release_fails_before_artifact_download(self):
        self.start()
        self.fixture.checksum_status = 404
        self.fixture.checksums = b"No checksum asset on this old release"
        result = self.run_shell(f"fetch_tarball {shlex.quote(str(self.dest))}")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SHA256SUMS", result.stderr)
        self.assertEqual(self.artifacts(), [])
        self.assertFalse(any(item["path"].endswith("/releases/latest") for item in self.fixture.requests))

    def test_local_archive_rejects_invalid_gzip_without_network(self):
        self.start()
        local = self.directory / "invalid-local.tar.gz"
        local.write_bytes(b"invalid compressed archive")
        result = self.run_shell(
            f"XUI_LOCAL_TARBALL={shlex.quote(str(local))}; fetch_tarball {shlex.quote(str(self.dest))}"
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.requests, [])

    def test_local_valid_archive_requires_no_network(self):
        self.start()
        local = self.directory / "local.tar.gz"
        local.write_bytes(PAYLOAD)
        result = self.run_shell(
            f"XUI_LOCAL_TARBALL={shlex.quote(str(local))}; fetch_tarball {shlex.quote(str(self.dest))}"
        )
        self.assert_valid(result)
        self.assertEqual(self.fixture.requests, [])

    def test_failed_download_never_reaches_service_stop_or_live_mutation(self):
        self.start("errors")
        source = (ROOT / "install.sh").read_text()
        installer = re.search(r"(?ms)^install_x_ui\(\) \{\n.*?^\}", source)
        self.assertIsNotNone(installer)
        with self.helpers.open("a") as output:
            output.write("\n" + installer.group(0) + "\n")
        live = self.directory / "installed"
        live.mkdir()
        sentinel = live / "x-ui"
        sentinel.write_bytes(b"existing live binary is untouched\n")
        marker = self.directory / "mutation-attempted"
        url = f"http://127.0.0.1:{self.fixture.server_port}/artifact"
        invocation = (
            f"xui_folder={shlex.quote(str(live))}\n"
            f"db_folder={shlex.quote(str(self.directory / 'db'))}\n"
            f"unit_file={shlex.quote(str(self.directory / 'unit'))}\n"
            f"stage={shlex.quote(str(self.directory / 'stage'))}\n"
            f"stage_release() {{ download_tarball {shlex.quote(url)} {shlex.quote(str(self.dest))} {DIGEST}; }}\n"
            f"record_mutation() {{ printf '%s\\n' \"$*\" >> {shlex.quote(str(marker))}; return 99; }}\n"
            # Intercept every mutation in install_x_ui, even if a regression
            # unexpectedly lets staging return success. None may reach host
            # paths or the real service manager.
            "systemctl() { record_mutation systemctl \"$@\"; }\n"
            "mkdir() { record_mutation mkdir \"$@\"; }\n"
            "mv() { record_mutation mv \"$@\"; }\n"
            "rm() { record_mutation rm \"$@\"; }\n"
            "install() { record_mutation install \"$@\"; }\n"
            "fail() { die \"$*\"; }\n"
            "install_x_ui"
        )
        result = self.run_shell(invocation)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), "failed staging reached a live mutation")
        self.assertEqual(sentinel.read_bytes(), b"existing live binary is untouched\n")

    def test_large_latest_metadata_and_pinned_release(self):
        self.start("interrupted")
        result = self.run_shell(f"XUI_TAG=; fetch_tarball {shlex.quote(str(self.dest))}")
        self.assert_valid(result)
        paths = [item["path"] for item in self.fixture.requests]
        self.assertEqual(sum(path.endswith("/releases/latest") for path in paths), 1)
        self.assertIn(f"/fixture/repo/releases/download/{TAG}/SHA256SUMS", paths)
        for request in self.artifacts():
            self.assertEqual(request["path"], f"/fixture/repo/releases/download/{TAG}/{ASSET}")
        self.assertNotIn("curl: (23)", result.stderr)
        self.assertEqual([item["range"] for item in self.artifacts()], ["", "bytes=65536-"])


if __name__ == "__main__":
    if not REAL_CURL:
        raise SystemExit("curl is required")
    unittest.main(verbosity=2)
