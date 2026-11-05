#!/usr/bin/env python3
"""Measure TCP EOF-response support before attributing native-protocol failures.

Run with --netns. Uses only synthetic loopback traffic and untouched supplied
executables: direct TCP, then stock, main-client, and server SOCKS -> freedom.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

BODY = b'half-close-control\x00' * 215 + b'X' * 11


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise EOFError('connection ended before response')
        data.extend(block)
    return bytes(data)


class Target(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            self.request.sendall(exact(self.request, len(BODY)))
        except OSError:
            pass


class EOFHandler(socketserver.BaseRequestHandler):
    # Same EOF-dependent request semantics and five-second read timeout as the
    # stress harness. Observations distinguish upload delivery from EOF support.
    def handle(self):
        observation = {'uploadedBytes': 0, 'eofObserved': False, 'replySent': False}
        self.request.settimeout(5)
        try:
            body = bytearray()
            while True:
                block = self.request.recv(4096)
                if not block:
                    observation['eofObserved'] = True
                    break
                body.extend(block)
                observation['uploadedBytes'] = len(body)
                if len(body) > 65536:
                    raise ValueError('EOF fixture request too large')
            self.request.sendall(hashlib.sha256(body).digest())
            observation['replySent'] = True
        except (OSError, ValueError) as error:
            observation['targetError'] = type(error).__name__
        finally:
            self.server.observations.append(observation)


def connect(socks, target):
    sock = socket.create_connection(('127.0.0.1', socks or target), timeout=5)
    sock.settimeout(5)
    if socks:
        try:
            sock.sendall(b'\x05\x01\x00')
            if exact(sock, 2) != b'\x05\x00':
                raise ValueError('SOCKS authentication rejected')
            sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target))
            head = exact(sock, 4)
            if head[:3] != b'\x05\x00\x00':
                raise ValueError('SOCKS connect rejected')
            size = 4 if head[3] == 1 else 16 if head[3] == 4 else exact(sock, 1)[0] if head[3] == 3 else 0
            if not size:
                raise ValueError('SOCKS response address invalid')
            exact(sock, size + 2)
        except Exception:
            sock.close()
            raise
    return sock


def classify(ordinary_ok, response_ok, observation):
    if not ordinary_ok:
        return 'control_failed'
    if response_ok:
        return 'supported'
    if observation.get('uploadedBytes') == len(BODY):
        return 'unsupported_eof_response'
    return 'inconclusive'


def probe(name, socks, echo, eof):
    result = {'name': name, 'ordinaryTransfer': False, 'halfCloseResponse': False}
    try:
        with connect(socks, echo.server_address[1]) as sock:
            sock.sendall(BODY)
            result['ordinaryTransfer'] = exact(sock, len(BODY)) == BODY
    except Exception as error:
        result['ordinaryError'] = type(error).__name__
    before = len(eof.observations)
    start = time.monotonic()
    try:
        with connect(socks, eof.server_address[1]) as sock:
            sock.sendall(BODY)
            sock.shutdown(socket.SHUT_WR)
            result['halfCloseResponse'] = exact(sock, 32) == hashlib.sha256(BODY).digest()
    except Exception as error:
        result['halfCloseError'] = type(error).__name__
    result['seconds'] = round(time.monotonic() - start, 3)
    until = time.monotonic() + 5.2
    while len(eof.observations) == before and time.monotonic() < until:
        time.sleep(0.02)
    observation = eof.observations[before] if len(eof.observations) > before else {}
    result['targetObservation'] = observation
    result['status'] = classify(result['ordinaryTransfer'], result['halfCloseResponse'], observation)
    return result


def config(port):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [{'protocol': 'freedom', 'settings': {}}]}


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run_core(name, binary, work, echo, eof):
    port = free_port()
    path = work / (name + '.json')
    path.write_text(json.dumps(config(port)))
    with (work / (name + '.log')).open('w') as log:
        process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            until = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    return {'name': name, 'status': 'startup_failed', 'exitCode': process.returncode}
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= until:
                        return {'name': name, 'status': 'startup_timeout'}
                    time.sleep(0.05)
            return probe(name, port, echo, eof)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)


def main(args):
    os.umask(0o077)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    binaries = [(name, getattr(args, flag).resolve()) for name, flag in [('stock', 'stock_core'), ('main-client', 'client_core'), ('server', 'server_core')]]
    metadata = {name: {'path': str(path), 'sha256': digest(path)} for name, path in binaries}
    echo, eof = Target(('127.0.0.1', 0), EchoHandler), Target(('127.0.0.1', 0), EOFHandler)
    eof.observations = []
    for target in (echo, eof):
        threading.Thread(target=target.serve_forever, daemon=True).start()
    results = []
    report = {'binaries': metadata, 'bodyBytes': len(BODY), 'results': results, 'complete': False}
    try:
        results.append(probe('direct-tcp', None, echo, eof))
        for name, path in binaries:
            results.append(run_core(name, path, work, echo, eof))
        report['binariesUnchanged'] = all(digest(path) == metadata[name]['sha256'] for name, path in binaries)
        report['complete'] = True
    finally:
        for target in (echo, eof):
            target.shutdown()
            target.server_close()
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    reliable = report['complete'] and report['binariesUnchanged'] and results[0]['status'] == 'supported'
    reliable = reliable and all(item['status'] in ('supported', 'unsupported_eof_response') for item in results)
    return 0 if reliable else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stock-core', 'client-core', 'server-core', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--netns', action='store_true')
    args = parser.parse_args()
    if args.netns:
        os.environ['D11_HALFCLOSE_HOST_NETNS'] = os.readlink('/proc/self/ns/net')
        os.execvp('unshare', ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()), *[item for item in sys.argv[1:] if item != '--netns']])
    if not os.environ.get('D11_HALFCLOSE_HOST_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['D11_HALFCLOSE_HOST_NETNS']:
        parser.error('invoke with --netns')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    if subprocess.check_output(['ip', 'route', 'show', 'default'], text=True).strip():
        parser.error('isolated fixture namespace unexpectedly has a default route')
    raise SystemExit(main(args))
