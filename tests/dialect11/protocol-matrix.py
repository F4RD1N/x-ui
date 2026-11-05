#!/usr/bin/env python3
"""Disposable panel/API/native protocol matrix. All traffic stays in a private netns.

Uses fixtures from the selected worktree; never edits or rebuilds a client core.
Each selected-client response is saved, hashed, parsed and executed unchanged.
Outbound-only settings can independently be exercised through the panel template.
"""
import argparse
import base64
import copy
import concurrent.futures
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.umask(0o077)
SOCKS = 10808
DUPLEX_PORT = 28007
EOF_PORT = 28008
V6_TARGET = 'fd00:198:18::1'
DEFAULT_TRANSFER_BYTES = 1024 * 1024
MAX_TRANSFER_BYTES = 16 * 1024 * 1024


def transfer_payload(direction, size):
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_TRANSFER_BYTES:
        raise ValueError('transferBytes must be an integer from1 to16777216')
    prefix = (direction + '-').encode('ascii')
    return (prefix + bytes(range(256)) * ((max(0, size - len(prefix)) + 255) // 256))[:size]


UPSTREAM = transfer_payload('upload', DEFAULT_TRANSFER_BYTES)
DOWNSTREAM = transfer_payload('download', DEFAULT_TRANSFER_BYTES)
METRICS = []
UDP_THREADS = {}
h = d = n = None


def load_helpers(repo):
    global h, d, n
    path = repo / 'tests/dialect11/native-client-config-e2e.py'
    spec = importlib.util.spec_from_file_location('matrix_native_copy', path)
    n = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(n)
    d, h = n.d, n.d.h


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def merge(base, patch):
    """RFC7396 merge semantics: null deletes, arrays replace."""
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict):
            out[key] = merge(out.get(key, {}) if isinstance(out.get(key), dict) else {}, value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class TransferReadError(AssertionError):
    def __init__(self, context, received, expected, reason):
        self.progress = dict(context, receivedBytes=received, expectedBytes=expected, reason=reason)
        super().__init__(str(context.get('phase', 'transfer')) + ': received ' + str(received) + '/' + str(expected) + ' bytes before ' + reason)


def exact(sock, count, context=None):
    data = bytearray()
    while len(data) < count:
        try:
            chunk = sock.recv(min(65536, count - len(data)))
        except OSError as error:
            if context is not None:
                raise TransferReadError(context, len(data), count, type(error).__name__) from error
            raise
        if not chunk:
            if context is not None:
                raise TransferReadError(context, len(data), count, 'EOF')
            raise AssertionError('connection ended before expected bytes')
        data.extend(chunk)
    return bytes(data)


def parse_udp_snmp(text):
    rows = [line.split() for line in text.splitlines() if line.startswith('Udp:')]
    if len(rows) < 2 or len(rows[0]) != len(rows[1]):
        return {}
    return {name: int(value) for name, value in zip(rows[0][1:], rows[1][1:])}


def parse_udp_socket_table(text, family):
    sockets = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 13:
            continue
        try:
            port = int(fields[1].rsplit(':', 1)[1], 16)
            tx, rx = (int(value, 16) for value in fields[4].split(':'))
            sockets.append({'family': family, 'localPort': port, 'txQueueBytes': tx, 'rxQueueBytes': rx, 'drops': int(fields[-1])})
        except (ValueError, IndexError):
            continue
    return sorted(sockets, key=lambda item: (item['family'], item['localPort'], item['drops']))


def udp_snapshot():
    result = {'scope': 'current-network-namespace', 'monotonicSeconds': round(time.monotonic(), 6),
              'udp4': {}, 'udp6': {}, 'sockets': [], 'readErrors': []}
    for file, family in (('snmp', 'udp4'), ('snmp6', 'udp6'), ('udp', 'udp4'), ('udp6', 'udp6')):
        try:
            text = Path('/proc/net/' + file).read_text()
            if file == 'snmp':
                result['udp4'] = parse_udp_snmp(text)
            elif file == 'snmp6':
                result['udp6'] = {line.split()[0]: int(line.split()[1]) for line in text.splitlines() if line.startswith('Udp6')}
            else:
                result['sockets'].extend(parse_udp_socket_table(text, family))
        except (OSError, ValueError, IndexError) as error:
            result['readErrors'].append({'file': file, 'error': type(error).__name__})
    return result


def udp_delta(before, after):
    result = {'udp4': {}, 'udp6': {}, 'sockets': []}
    for family in ('udp4', 'udp6'):
        result[family] = {key: after[family][key] - value for key, value in before[family].items() if key in after[family]}
    def grouped(snapshot):
        groups = {}
        for row in snapshot['sockets']:
            key = (row['family'], row['localPort'])
            group = groups.setdefault(key, {'count': 0, 'drops': 0, 'rx': 0, 'tx': 0})
            group['count'] += 1
            group['drops'] += row['drops']
            group['rx'] += row['rxQueueBytes']
            group['tx'] += row['txQueueBytes']
        return groups
    prior, current = grouped(before), grouped(after)
    for family, port in sorted(set(prior) | set(current)):
        old, new = prior.get((family, port)), current.get((family, port))
        same = old is not None and new is not None and old['count'] == new['count'] and new['drops'] >= old['drops']
        result['sockets'].append({'family': family, 'localPort': port, 'beforeSocketCount': old['count'] if old else 0,
                                  'afterSocketCount': new['count'] if new else 0, 'dropsDelta': new['drops'] - old['drops'] if same else None,
                                  'rxQueueBytesBefore': old['rx'] if old else None, 'rxQueueBytesAfter': new['rx'] if new else None,
                                  'identityNote': 'Ports can be reused; per-socket delta is only a same-port observation, not proof of socket identity.'})
    return result


def socks_connect(port, destination, timeout):
    sock = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b'\x05\x01\x00')
        h.require(exact(sock, 2) == b'\x05\x00', 'SOCKS authentication negotiation failed')
        ipv6 = ':' in destination[0]
        address = socket.inet_pton(socket.AF_INET6, destination[0]) if ipv6 else socket.inet_aton(destination[0])
        sock.sendall(b'\x05\x01\x00' + (b'\x04' if ipv6 else b'\x01') + address + struct.pack('!H', destination[1]))
        header = exact(sock, 4)
        h.require(header[:3] == b'\x05\x00\x00', 'SOCKS connection rejected')
        if header[3] == 1:
            exact(sock, 4)
        elif header[3] == 4:
            exact(sock, 16)
        elif header[3] == 3:
            exact(sock, exact(sock, 1)[0])
        else:
            raise AssertionError('unexpected SOCKS address type')
        exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


class TrafficHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def answer(self, data):
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith('/download'):
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                size = int(query.get('bytes', [DEFAULT_TRANSFER_BYTES])[0])
                self.answer(transfer_payload('download', size))
            except (ValueError, TypeError):
                self.send_error(400)
        else:
            self.answer(h.BODY)

    def do_POST(self):
        count = int(self.headers.get('Content-Length', '0'))
        if not 0 <= count <= 16 * 1024 * 1024:
            self.send_error(413)
            return
        data = self.rfile.read(count)
        self.answer(json.dumps({'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}).encode())

    def log_message(self, *_):
        pass


class DuplexHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(90)
        failures = []
        def send():
            try:
                self.request.sendall(downstream)
            except OSError as error:
                failures.append(error)
        try:
            while True:
                marker = exact(self.request, 4)
                h.require(marker in (b'MX01', b'MX02'), 'invalid duplex marker')
                size = struct.unpack('!I', exact(self.request, 4))[0] if marker == b'MX02' else DEFAULT_TRANSFER_BYTES
                h.require(1 <= size <= MAX_TRANSFER_BYTES, 'invalid duplex transfer length')
                downstream = transfer_payload('download', size)
                sender = threading.Thread(target=send, daemon=True)
                sender.start()
                body = exact(self.request, size)
                sender.join(90)
                if sender.is_alive() or failures:
                    return
                self.request.sendall(hashlib.sha256(body).digest())
        except (OSError, AssertionError):
            pass


class EOFHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            body = bytearray()
            while True:
                block = self.request.recv(4096)
                if not block:
                    break
                body.extend(block)
                h.require(len(body) <= 65536, 'EOF fixture request too large')
            self.request.sendall(hashlib.sha256(body).digest())
        except (OSError, AssertionError):
            pass


class ThreadsTCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class HTTPv6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def targets(fixtures, cover_tls, ipv6=False, servers=None, sockets=None):
    servers = [] if servers is None else servers
    sockets = [] if sockets is None else sockets
    for port, tls in ((h.HTTP_PORT, False), (h.TLS_PORT, True)):
        server = http.server.ThreadingHTTPServer(('127.0.0.1' if tls else h.TARGET, port), TrafficHTTP)
        servers.append(server)
        server.daemon_threads = True
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2 if cover_tls != '1.3' else ssl.TLSVersion.TLSv1_3
            if cover_tls == '1.2':
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(fixtures / 'server.crt', fixtures / 'server.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    duplex = ThreadsTCP((h.TARGET, DUPLEX_PORT), DuplexHandler)
    threading.Thread(target=duplex.serve_forever, daemon=True).start()
    servers.append(duplex)
    holder = ThreadsTCP((h.TARGET, EOF_PORT), EOFHandler)
    threading.Thread(target=holder.serve_forever, daemon=True).start()
    servers.append(holder)
    if ipv6:
        server = HTTPv6((V6_TARGET, h.HTTP_PORT), TrafficHTTP)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    def start_echo(family, address):
        udp = socket.socket(family, socket.SOCK_DGRAM)
        sockets.append(udp)
        udp.bind((address, h.UDP_PORT))
        udp.settimeout(.2)
        def echo():
            while True:
                try:
                    data, peer = udp.recvfrom(65535)
                    if not peer:
                        return
                    udp.sendto(data, peer)
                except socket.timeout:
                    continue
                except OSError:
                    return
        thread = threading.Thread(target=echo, daemon=True)
        UDP_THREADS[id(udp)] = thread
        thread.start()
    start_echo(socket.AF_INET, h.TARGET)
    if ipv6:
        start_echo(socket.AF_INET6, V6_TARGET)
    return servers, sockets


def close_udp(udp):
    # close() alone does not wake a blocked recvfrom in another thread on Linux;
    # the open-file description then holds the old bind through the next case.
    if isinstance(udp, list):
        for item in udp:
            close_udp(item)
        return
    try:
        udp.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    udp.close()
    thread = UDP_THREADS.pop(id(udp), None)
    if thread:
        thread.join(2)
        h.require(not thread.is_alive(), 'UDP target thread did not stop')


def dns_resolver_fixture(case, scenario, fixtures):
    spec = scenario.get('dnsResolver')
    if not spec:
        return None
    h.require(case['protocol'] == 'dnstt', 'DNS resolver fixture is only valid for DNSTT')
    transport = spec['transport']
    h.require(transport in ('udp', 'dot', 'doh'), 'unknown DNS resolver transport fixture')
    hostname = 'e2e.test' if spec.get('hostname', True) else '127.0.0.1'
    recovering = spec.get('unavailableFirst', False)
    port = case['port'] if transport == 'udp' and not recovering else 28100
    resolver = {'transport': transport, 'address': f'{hostname}:{port}'}
    if hostname != '127.0.0.1':
        resolver['bootstrap'] = '127.0.0.1'
    if transport != 'udp':
        resolver.update(serverName='e2e.test', caPem=(fixtures / 'ca.crt').read_text())
        if spec.get('fingerprint'):
            resolver['fingerprint'] = spec['fingerprint']
    if transport == 'doh':
        resolver['address'] = f'https://{hostname}:{port}/dns-query'
    resolvers = [resolver]
    stats, stats_lock = {'unavailableQueries': 0, 'availableQueries': 0, 'availableResponses': 0}, threading.Lock()
    if recovering:
        resolvers.insert(0, {'transport': 'udp', 'address': '127.0.0.1:28101'})
        case['_resolverStats'] = stats
    case['settings'].setdefault('clientExport', {})['resolvers'] = resolvers
    if transport == 'udp' and not recovering:
        return None

    def exchange(query):
        with stats_lock:
            stats['availableQueries'] += 1
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(15)
            sock.connect(('127.0.0.1', case['port']))
            sock.send(query)
            response = sock.recv(65535)
            with stats_lock:
                stats['availableResponses'] += 1
            return response

    class UDPForward(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            try:
                sock.sendto(exchange(query), self.client_address)
            except OSError:
                pass

    class Unavailable(socketserver.BaseRequestHandler):
        def handle(self):
            # Deliberately unavailable resolver: record receipt, never answer.
            with stats_lock:
                stats['unavailableQueries'] += 1

    class ResolverGroup:
        def __init__(self, members):
            self.members = members
        def shutdown(self):
            for member in self.members:
                member.shutdown()
        def server_close(self):
            for member in self.members:
                member.server_close()

    class DoT(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(30)
            write_lock = threading.Lock()
            capacity = threading.BoundedSemaphore(256)
            def answer(query):
                try:
                    response = exchange(query)
                    with write_lock:
                        self.request.sendall(struct.pack('!H', len(response)) + response)
                except OSError:
                    pass
                finally:
                    capacity.release()
            try:
                while True:
                    length = struct.unpack('!H', exact(self.request, 2))[0]
                    h.require(0 < length <= 65535, 'invalid DNS TCP frame')
                    query = exact(self.request, length)
                    if not capacity.acquire(timeout=15):
                        return
                    threading.Thread(target=answer, args=(query,), daemon=True).start()
            except (OSError, AssertionError):
                pass

    class DoH(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def do_POST(self):
            if self.path != '/dns-query' or self.headers.get_content_type() != 'application/dns-message':
                self.send_error(400)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                h.require(0 < length <= 65535, 'invalid DoH body length')
                response = exchange(self.rfile.read(length))
                self.send_response(200)
                self.send_header('Content-Type', 'application/dns-message')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except (OSError, AssertionError, ValueError):
                self.send_error(502)
        def log_message(self, *_):
            pass

    if transport == 'udp':
        server = socketserver.ThreadingUDPServer(('127.0.0.1', port), UDPForward)
    elif transport == 'dot':
        server = ThreadsTCP(('127.0.0.1', port), DoT)
    else:
        server = http.server.ThreadingHTTPServer(('127.0.0.1', port), DoH)
    server.daemon_threads = True
    if transport != 'udp':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['dot'] if transport == 'dot' else ['http/1.1'])
        context.load_cert_chain(fixtures / 'server.crt', fixtures / 'server.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if recovering:
        unavailable = socketserver.ThreadingUDPServer(('127.0.0.1', 28101), Unavailable)
        unavailable.daemon_threads = True
        threading.Thread(target=unavailable.serve_forever, daemon=True).start()
        return ResolverGroup([unavailable, server])
    return server


def http_request(port, method='GET', path='/echo', body=None, timeout=45, destination=None):
    start = time.monotonic()
    destination = destination or h.TARGET
    connection = http.client.HTTPConnection(destination, h.HTTP_PORT, timeout=timeout)
    connection.sock = socks_connect(port, (destination, h.HTTP_PORT), timeout)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        received = response.read()
        h.require(response.status == 200, 'HTTP target status ' + str(response.status))
        return received, time.monotonic() - start
    finally:
        connection.close()


def udp_series(port, sizes, timeout=15, destination=None):
    destination = destination or h.TARGET
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as control:
        control.settimeout(timeout)
        control.sendall(b'\x05\x01\x00')
        h.require(exact(control, 2) == b'\x05\x00', 'SOCKS authentication negotiation failed')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        header = exact(control, 4)
        h.require(header[:3] == b'\x05\x00\x00', 'SOCKS UDP rejected')
        address = n.socks_address(control, header[3])
        relay_port = struct.unpack('!H', exact(control, 2))[0]
        if address in ('0.0.0.0', '::'):
            address = '127.0.0.1'
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            ipv6 = ':' in destination
            packed = socket.inet_pton(socket.AF_INET6, destination) if ipv6 else socket.inet_aton(destination)
            samples = []
            for size in sizes:
                payload = os.urandom(size)
                frame = b'\x00\x00\x00' + (b'\x04' if ipv6 else b'\x01') + packed + struct.pack('!H', h.UDP_PORT) + payload
                start = time.monotonic()
                sock.sendto(frame, (address, relay_port))
                reply, _ = sock.recvfrom(65535)
                h.require(reply[:3] == b'\x00\x00\x00', 'fragmented/invalid SOCKS UDP response')
                offset = 8 if reply[3] == 1 else 20 if reply[3] == 4 else 5 + reply[4] if reply[3] == 3 else -1
                h.require(offset > 0 and reply[offset + 2:] == payload, 'UDP integrity mismatch')
                samples.append({'bytes': size, 'roundTripMs': round((time.monotonic() - start) * 1000, 3)})
            return samples


def udp_probe(port, payload_bytes=1200, timeout=15, destination=None):
    return udp_series(port, [payload_bytes], timeout, destination)[0]['roundTripMs'] / 1000


def flow_capacity_probe(port):
    def transfer(owner):
        failures = []
        def send():
            try:
                owner.sendall(UPSTREAM)
            except OSError as error:
                failures.append(error)
        owner.sendall(b'MX01')
        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        downloaded = exact(owner, len(DOWNSTREAM))
        uploaded = exact(owner, 32)
        sender.join(30)
        h.require(not sender.is_alive() and not failures, 'capacity owner upload failed')
        h.require(downloaded == DOWNSTREAM, 'capacity owner download integrity mismatch')
        h.require(uploaded == hashlib.sha256(UPSTREAM).digest(), 'capacity owner upload integrity mismatch')
    with socks_connect(port, (h.TARGET, DUPLEX_PORT), 30) as owner:
        started = time.monotonic()
        transfer(owner)
        denied = False
        try:
            http_request(port, timeout=2)
        except (OSError, AssertionError, http.client.HTTPException):
            denied = True
        h.require(denied, 'second concurrent flow bypassed maxStreams/maxFlowsPerSession=1')
        transfer(owner)
        return time.monotonic() - started


def half_close_probe(port):
    body = UPSTREAM[:4096]
    with socks_connect(port, (h.TARGET, EOF_PORT), 5) as sock:
        started = time.monotonic()
        sock.sendall(body)
        sock.shutdown(socket.SHUT_WR)
        h.require(exact(sock, 32) == hashlib.sha256(body).digest(), 'EOF response integrity mismatch')
        return time.monotonic() - started


def duplex_probe(port, timeout=60, duration=0, transfer_bytes=DEFAULT_TRANSFER_BYTES, result_stats=None, udp_diagnostics=False):
    failures = []
    upstream = transfer_payload('upload', transfer_bytes)
    downstream = transfer_payload('download', transfer_bytes)
    with socks_connect(port, (h.TARGET, DUPLEX_PORT), timeout) as sock:
        submitted = threading.Event()
        def send():
            try:
                sock.sendall(upstream)
                submitted.set()
            except OSError as error:
                failures.append(error)
        start = time.monotonic()
        rounds = 0
        while True:
            sock.sendall(b'MX02' + struct.pack('!I', transfer_bytes))
            submitted.clear()
            sender = threading.Thread(target=send, daemon=True)
            sender.start()
            try:
                got = exact(sock, len(downstream), {'phase': 'duplex-download-body', 'direction': 'download', 'round': rounds + 1})
                checksum = exact(sock, 32, {'phase': 'duplex-upload-acknowledgement', 'direction': 'upload-acknowledgement', 'round': rounds + 1})
            except Exception as error:
                error.transferDiagnostics = {'progress': getattr(error, 'progress', {}), 'uploadSubmissionCompleted': submitted.is_set(),
                                             'uploadBytesSubmitted': len(upstream) if submitted.is_set() else None,
                                             'submissionDoesNotConfirmRemoteReceipt': True,
                                             'uploadErrorTypes': [type(item).__name__ for item in failures]}
                if udp_diagnostics:
                    error.transferDiagnostics['udpAtFailure'] = udp_snapshot()
                raise
            sender.join(timeout)
            h.require(not sender.is_alive() and not failures, 'full-duplex upload did not complete')
            h.require(got == downstream, 'full-duplex download integrity mismatch')
            h.require(checksum == hashlib.sha256(upstream).digest(), 'full-duplex upload integrity mismatch')
            rounds += 1
            if time.monotonic() - start >= duration:
                break
            time.sleep(.1)
        if result_stats is not None:
            result_stats.update(rounds=rounds, uploadBytes=rounds * len(upstream), downloadBytes=rounds * len(downstream))
        return time.monotonic() - start


def run_checks(case, port, path):
    prefix = path + '.' + case['name']
    transfer_bytes = case.get('transferBytes', DEFAULT_TRANSFER_BYTES)
    transfer_timeout = case.get('transferTimeoutSeconds', 45)
    upstream = transfer_payload('upload', transfer_bytes)
    downstream = transfer_payload('download', transfer_bytes)
    resolver_before = dict(case.get('_resolverStats', {}))
    kinds = ['latency', 'download', 'upload', 'duplex', 'reconnect']
    if case.get('halfClose'):
        kinds.append('half-close')
    if case.get('ipv6'):
        kinds += ['ipv6-http']
    if case.get('concurrentStreams', 1) > 1:
        kinds.append('concurrent-streams')
    if case.get('sustainSeconds', 0) > 0:
        kinds.append('sustained-duplex')
    # UDP has no stream FIN. With a one-flow capacity it legitimately occupies
    # the sole server slot until policy idle expiry, so exercise it last and
    # reuse one association for all packet-size boundaries.
    kinds.append('udp')
    if case.get('ipv6') and case.get('udp', True) and not case.get('singleFlowCapacity'):
        kinds.append('ipv6-udp')
    if case.get('singleFlowCapacity'):
        # A one-flow limit tests admission semantics, not rapid turnover of
        # independent TCP/UDP flows. Recovery is measured by the caller after
        # terminating the owning process/core, preserving the same limit.
        kinds = ['flow-capacity']
    for kind in kinds:
        if kind == 'udp' and not case.get('udp', True):
            METRICS.append({'case': case['name'], 'path': path, 'check': kind, 'status': 'unsupported'})
            continue
        udp_before = udp_snapshot() if case.get('udpDiagnostics') else None
        try:
            metric = {'case': case['name'], 'path': path, 'check': kind}
            if kind == 'flow-capacity':
                metric.update(allowedFlows=1, excessFlowDenied=True, ownerSurvivedDenial=True,
                              seconds=flow_capacity_probe(port), uploadBytes=2 * len(UPSTREAM), downloadBytes=2 * len(DOWNSTREAM))
            elif kind == 'latency':
                samples = []
                for _ in range(3):
                    data, elapsed = http_request(port)
                    h.require(data == h.BODY, 'latency body integrity mismatch')
                    samples.append(round(elapsed * 1000, 3))
                    time.sleep(max(.05, case.get('interCheckDelaySeconds', 0)))
                metric.update(samplesMs=samples, medianMs=statistics.median(samples))
            elif kind == 'download':
                data, elapsed = http_request(port, path='/download?bytes=' + str(transfer_bytes), timeout=transfer_timeout)
                h.require(data == downstream, 'download integrity mismatch')
                metric.update(bytes=len(data), seconds=elapsed, mebibytesPerSecond=len(data) / elapsed / 1048576)
            elif kind == 'upload':
                data, elapsed = http_request(port, 'POST', '/upload', upstream, timeout=transfer_timeout)
                received = json.loads(data)
                h.require(received == {'bytes': len(upstream), 'sha256': hashlib.sha256(upstream).hexdigest()}, 'upload integrity mismatch')
                metric.update(bytes=len(upstream), seconds=elapsed, mebibytesPerSecond=len(upstream) / elapsed / 1048576)
            elif kind == 'duplex':
                elapsed = duplex_probe(port, timeout=max(60, transfer_timeout), transfer_bytes=transfer_bytes, udp_diagnostics=case.get('udpDiagnostics', False))
                metric.update(uploadBytes=len(upstream), downloadBytes=len(downstream), seconds=elapsed)
            elif kind == 'udp':
                if case.get('singleFlowCapacity'):
                    metric['samples'] = udp_series(port, (32, 512, 1200))
                    metric['sharedAssociation'] = True
                else:
                    metric['samples'] = []
                    for size in (32, 512, 1200):
                        metric['samples'].append({'bytes': size, 'roundTripMs': round(udp_probe(port, size) * 1000, 3)})
                        time.sleep(case.get('interCheckDelaySeconds', 0))
            elif kind == 'reconnect':
                duration = float(case.get('durationSeconds', .3))
                time.sleep(min(duration, 5))
                data, elapsed = http_request(port)
                h.require(data == h.BODY, 'reconnect integrity mismatch')
                metric['roundTripMs'] = round(elapsed * 1000, 3)
            elif kind == 'ipv6-http':
                data, elapsed = http_request(port, destination=V6_TARGET)
                h.require(data == h.BODY, 'IPv6 HTTP integrity mismatch')
                metric['roundTripMs'] = round(elapsed * 1000, 3)
            elif kind == 'ipv6-udp':
                metric['roundTripMs'] = round(udp_probe(port, destination=V6_TARGET) * 1000, 3)
            elif kind == 'concurrent-streams':
                count = case['concurrentStreams']
                with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
                    futures = [executor.submit(duplex_probe, port, timeout=max(60, transfer_timeout), transfer_bytes=transfer_bytes,
                                               udp_diagnostics=case.get('udpDiagnostics', False)) for _ in range(count)]
                    metric['seconds'] = [future.result(timeout=max(75, transfer_timeout + 15)) for future in futures]
                metric['streams'] = count
                metric['uploadBytesPerStream'], metric['downloadBytesPerStream'] = len(upstream), len(downstream)
            elif kind == 'sustained-duplex':
                metric['seconds'] = duplex_probe(port, timeout=max(60, transfer_timeout), duration=case['sustainSeconds'],
                                                 transfer_bytes=transfer_bytes, result_stats=metric, udp_diagnostics=case.get('udpDiagnostics', False))
                metric['requestedSeconds'] = case['sustainSeconds']
                metric['sameConnection'] = True
            elif kind == 'half-close':
                metric['seconds'] = half_close_probe(port)
                metric['requestBytes'] = 4096
                metric['classification'] = 'EOF-compatibility-diagnostic'
            metric['status'] = 'pass'
            METRICS.append(metric)
            h.result(prefix + '.' + kind, True)
        except Exception as error:
            failed = {'case': case['name'], 'path': path, 'check': kind, 'status': 'fail', 'error': str(error)[:300]}
            if hasattr(error, 'transferDiagnostics'):
                failed['transferDiagnostics'] = error.transferDiagnostics
            METRICS.append(failed)
            h.result(prefix + '.' + kind, False, error)
        finally:
            if udp_before is not None:
                udp_after = udp_snapshot()
                METRICS.append({'case': case['name'], 'path': path, 'check': 'udp-diagnostics', 'stage': kind, 'status': 'observed',
                                'before': udp_before, 'after': udp_after, 'delta': udp_delta(udp_before, udp_after)})
        time.sleep(case.get('interCheckDelaySeconds', 0))
    if resolver_before:
        observed = {key: value - resolver_before[key] for key, value in case['_resolverStats'].items()}
        traffic_ok = all(any(item['name'] == prefix + '.' + check and item['ok'] for item in h.RESULTS)
                         for check in ('latency', 'download', 'upload'))
        ok = traffic_ok and all(observed[key] > 0 for key in ('unavailableQueries', 'availableQueries', 'availableResponses'))
        METRICS.append({'case': case['name'], 'path': path, 'check': 'multi-resolver-recovery', 'status': 'pass' if ok else 'fail',
                        'observed': observed, 'trafficIntegrityPassed': traffic_ok,
                        'semantics': 'Round-robin queries plus KCP recovery; first member deliberately never replies.'})
        h.result(prefix + '.multi-resolver-recovery-observed', ok, 'controlled resolver counters: ' + str(observed))


def control_key(panel, case, scenario):
    kind = scenario.get('tlsControl')
    if not kind:
        return
    cert = case['settings'].setdefault('certificates', {})
    user = case['settings']['clients'][0]
    for name in ('tlsAuth', 'tlsCrypt', 'tlsCryptV2', 'keyDirection'):
        cert.pop(name, None)
        user.pop(name, None)
    if kind == 'tlsCryptV2':
        server = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'openvpn-tls-crypt-v2-server'})
        client = panel.api('POST', '/panel/api/server/native/credentials', json={'kind': 'openvpn-tls-crypt-v2', 'serverKey': server['serverKey']})
        cert[kind] = server['serverKey']
        user[kind] = client['clientKey']
    else:
        raw = os.urandom(256).hex()
        cert[kind] = '-----BEGIN OpenVPN Static key V1-----\n' + '\n'.join(raw[i:i + 32] for i in range(0, len(raw), 32)) + '\n-----END OpenVPN Static key V1-----\n'
        if kind == 'tlsAuth' and scenario.get('tlsAuthDirection') is not None:
            cert['keyDirection'] = scenario['tlsAuthDirection']


def fixture(panel, scenario, presets, index):
    if scenario.get('base', 'generated') == 'generated':
        profile = d.request_profile(panel, scenario['protocol'])
        case = {'protocol': scenario['protocol'], 'settings': profile['settings'], 'stream': profile.get('streamSettings', {})}
        if case['protocol'] == 'shadowtls':
            case['settings']['handshake']['port'] = h.TLS_PORT
    else:
        case = copy.deepcopy(presets[scenario['base']])
    case.update(name=scenario['name'], port=29200 + index, udp=scenario.get('udp', True), durationSeconds=scenario.get('durationSeconds', .3),
                interCheckDelaySeconds=scenario.get('interCheckDelaySeconds', 0), ipv6=scenario.get('ipv6', False),
                sustainSeconds=scenario.get('sustainSeconds', scenario.get('durationSeconds', 0) if scenario.get('durationSeconds', 0) > 5 else 0),
                concurrentStreams=scenario.get('concurrentStreams', 1), halfClose=scenario.get('halfClose', False),
                listen=scenario.get('listen', '127.0.0.1'), transferBytes=scenario.get('transferBytes', DEFAULT_TRANSFER_BYTES),
                transferTimeoutSeconds=scenario.get('transferTimeoutSeconds', 45), udpDiagnostics=scenario.get('udpDiagnostics', False))
    transfer_payload('upload', case['transferBytes'])
    if not isinstance(case['transferTimeoutSeconds'], (int, float)) or isinstance(case['transferTimeoutSeconds'], bool) or not 1 <= case['transferTimeoutSeconds'] <= 180:
        raise ValueError('transferTimeoutSeconds must be between1 and180')
    case['settings'] = merge(case['settings'], scenario.get('settings', {}))
    case['stream'] = merge(case['stream'], scenario.get('stream', {}))
    user = merge(case['settings']['clients'][0], scenario.get('client', {}))
    user.update(email=case['name'] + '@matrix.test', subId='matrix' + uuid.uuid4().hex, enable=True)
    case['settings']['clients'][0] = user
    case['subid'] = user['subId']
    if case['protocol'] == 'shadowtls':
        inner = case['settings'].get('inner', {}).get('settings', {})
        for i, row in enumerate(inner.get('clients', [])):
            if i < len(case['settings']['clients']):
                row['email'] = case['settings']['clients'][i]['email']
    control_key(panel, case, scenario)
    limits = case['settings'].get('limits', {})
    case['singleSessionCapacity'] = case['settings'].get('maxSessions') == 1 or limits.get('maxSessions') == 1 or limits.get('maxSessionsPerIP') == 1
    case['singleFlowCapacity'] = (case['protocol'] == 'openvpn' and limits.get('maxFlowsPerSession') == 1) or (
        case['protocol'] == 'dnstt' and case['settings'].get('maxStreams') == 1 and case['singleSessionCapacity'])
    if scenario.get('sequentialFlowsOnly'):
        case['concurrentStreams'] = 1
    for limit in (case['settings'].get('maxStreams'), case['settings'].get('maxSessions'),
                  case['settings'].get('limits', {}).get('maxFlowsPerSession')):
        if isinstance(limit, int) and limit > 0:
            case['concurrentStreams'] = min(case['concurrentStreams'], limit)
    return case


def copied_config(panel, case):
    row = panel.api('GET', '/panel/api/inbounds/get/' + str(case['id']))
    h.require(row.get('listen') == case['listen'], 'inbound listen address changed during persistence')
    stored = json.loads(row['settings'])
    def assert_preserved(expected, actual, location):
        if isinstance(expected, dict):
            h.require(isinstance(actual, dict), location + ' changed type')
            for key, value in expected.items():
                if key in ('created_at', 'updated_at'):
                    continue
                h.require(key in actual, location + '.' + key + ' dropped during persistence')
                assert_preserved(value, actual[key], location + '.' + key)
        elif isinstance(expected, list):
            h.require(isinstance(actual, list) and len(actual) == len(expected), location + ' array changed length/type')
            for index, (value, saved) in enumerate(zip(expected, actual)):
                assert_preserved(value, saved, location + '[' + str(index) + ']')
        else:
            h.require(type(expected) is type(actual) and expected == actual, location + ' changed during persistence')
    assert_preserved(case['settings'], stored, 'settings')
    assert_preserved(case['stream'], json.loads(row['streamSettings']), 'streamSettings')
    h.result('api.' + case['name'] + '.persisted-fields', True)
    case['settings'] = stored
    config = n.copy_response(panel, case, case['settings']['clients'][0])
    if case['protocol'] == 'dnstt' and case['settings'].get('clientExport', {}).get('resolvers'):
        proxy = next(out for out in config['outbounds'] if out['tag'] == 'proxy')
        tunnel = proxy['settings'].get('tunnel', proxy['settings'])
        h.require(tunnel.get('resolvers') == case['settings']['clientExport']['resolvers'], 'resolver order/options changed during client export')
    if case['protocol'] == 'openvpn':
        server_cert = case['settings'].get('certificates', {})
        if 'keyDirection' in server_cert and server_cert.get('tlsAuth'):
            proxy = next(out for out in config['outbounds'] if out['tag'] == 'proxy')
            h.require(proxy['settings']['certificates']['keyDirection'] == 1 - server_cert['keyDirection'],
                      'exported TLS-auth direction is not reciprocal')
    return config


def parse(core, path, log, expect=True):
    proc = subprocess.run([str(core), 'run', '-test', '-c', str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=45, env=dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    log.write_text(proc.stdout)
    if expect is not None:
        h.require((proc.returncode == 0) == expect, 'client parser ' + ('rejected config' if expect else 'accepted invalid config'))
    return proc.returncode == 0


def openvpn_inline_settings(settings, form, inline_auth=None):
    """Encode generated public/client material, preserving explicit overrides."""
    if form not in ('string', 'array', 'base64'):
        raise ValueError('unknown OpenVPN outbound format')
    source = copy.deepcopy(settings)
    server, advanced = source['server'], source.get('advanced', {})
    certificates, crypto = source.get('certificates', {}), source.get('crypto', {})
    lines = ['client', 'dev ' + advanced.get('dev', 'tun'),
             'remote ' + str(server['address']) + ' ' + str(server['port']) + ' ' + server.get('network', 'udp')]
    if advanced.get('nobind', False):
        lines.append('nobind')
    if advanced.get('remoteCertTls'):
        lines.append('remote-cert-tls ' + advanced['remoteCertTls'])
    if crypto.get('cipher'):
        lines.append('cipher ' + crypto['cipher'])
    if crypto.get('dataCiphers'):
        lines.append('data-ciphers ' + ':'.join(crypto['dataCiphers']))
    if crypto.get('authHash'):
        lines.append('auth ' + crypto['authHash'])
    auth = source.get('auth', {})
    if auth.get('user') or inline_auth is not None:
        lines.append('auth-user-pass')
    if 'keyDirection' in certificates:
        lines.append('key-direction ' + str(certificates['keyDirection']))
    for name, tag in (('ca', 'ca'), ('cert', 'cert'), ('key', 'key'), ('tlsCrypt', 'tls-crypt'),
                      ('tlsAuth', 'tls-auth'), ('tlsCryptV2', 'tls-crypt-v2')):
        if certificates.get(name):
            material = certificates[name]
            if isinstance(material, list):
                material = '\n'.join(material)
            lines.extend(['<' + tag + '>', material.replace('\r\n', '\n').strip(), '</' + tag + '>'])
    if inline_auth is not None:
        lines.extend(['<auth-user-pass>', inline_auth['username'], inline_auth['password'], '</auth-user-pass>'])
    text = '\n'.join(lines) + '\n'
    result = {key: copy.deepcopy(source[key]) for key in ('domainStrategy', 'clientProof', 'username', 'password', 'mtu') if key in source}
    if auth.get('user'):
        result.update(username=auth['user'], password=auth.get('pass', ''))
    if advanced.get('mtu'):
        result['mtu'] = advanced['mtu']
    if form == 'base64':
        result['ovpnBase64'] = base64.b64encode(text.encode()).decode()
    else:
        result['ovpn'] = text.splitlines() if form == 'array' else text
    return result


def outbound_variant(config, scenario, folder):
    exported = copy.deepcopy(config)
    proxy = next(out for out in exported['outbounds'] if out['tag'] == 'proxy')
    if scenario.get('outboundFormat'):
        h.require(proxy['protocol'] == 'openvpn', 'outboundFormat requires OpenVPN')
        proxy['settings'] = openvpn_inline_settings(proxy['settings'], scenario['outboundFormat'], scenario.get('outboundInlineAuth'))
    if scenario.get('outboundSettings'):
        proxy['settings'] = merge(proxy['settings'], scenario['outboundSettings'])
    for protocol, patch in scenario.get('outboundProtocolSettings', {}).items():
        matches = [out for out in exported['outbounds'] if out['protocol'] == protocol]
        h.require(len(matches) == 1, 'outbound protocol patch must select exactly one handler')
        matches[0]['settings'] = merge(matches[0]['settings'], patch)
    if scenario.get('proofKeyFile'):
        h.require(proxy['protocol'] == 'openvpn', 'proofKeyFile requires OpenVPN')
        proof = proxy['settings']['clientProof']
        original = proof.pop('key')
        path = folder / 'proof-secret.hex'
        mode = scenario['proofKeyFile']
        h.require(mode in ('valid', 'missing', 'wrong'), 'unknown proofKeyFile fixture mode')
        if mode != 'missing':
            value = original if mode == 'valid' else ('0' if original[0] != '0' else '1') + original[1:]
            path.write_text(value + '\n')
            path.chmod(0o600)
        proof['keyFile'] = str(path)
    return exported


def copy_traffic(panel, client_core, case, path, folder, scenario):
    n.wait_native_listener(panel, case)
    expected_hash = digest(path)
    proc = h.launch([client_core, 'run', '-c', path], folder, folder / 'client.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        h.require(h.wait_port(SOCKS, 12), 'copied client did not listen')
        if scenario.get('expect') == 'deny':
            denied = False
            try:
                http_request(SOCKS, timeout=4)
            except (OSError, AssertionError, http.client.HTTPException):
                denied = True
            h.require(denied, 'negative fixture unexpectedly forwarded traffic')
            h.result('client.' + case['name'] + '.expected-denial', True)
            return
        run_checks(case, SOCKS, 'client')
    finally:
        h.stop(proc)
        h.require(digest(path) == expected_hash, 'returned client JSON changed')
    h.result('client.' + case['name'] + '.unchanged-export', True)
    panel.api('POST', '/panel/api/server/stopXrayService')
    proc = h.launch([client_core, 'run', '-c', path], folder, folder / 'stopped-server.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        h.require(h.wait_port(SOCKS, 12), 'stopped-server control client did not listen')
        for kind in ('tcp', 'udp') if case.get('udp', True) else ('tcp',):
            denied = False
            try:
                if kind == 'tcp':
                    http_request(SOCKS, timeout=2)
                else:
                    udp_probe(SOCKS, timeout=2)
            except (OSError, AssertionError, http.client.HTTPException):
                denied = True
            h.require(denied, 'export bypassed stopped native server using direct ' + kind)
            h.result('client.' + case['name'] + '.no-direct-' + kind + '-bypass', True)
    finally:
        h.stop(proc)
        panel.restart()
    if case.get('singleFlowCapacity') and case.get('udp', True):
        # Clear the old packet/session owner instead of assuming that closing a
        # SOCKS control socket immediately expires an IP/UDP association.
        proc = h.launch([client_core, 'run', '-c', path], folder, folder / 'capacity-recovery-udp.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
        try:
            h.require(h.wait_port(SOCKS, 12), 'capacity recovery client did not listen')
            samples = udp_series(SOCKS, (32, 512, 1200))
            METRICS.append({'case': case['name'], 'path': 'client', 'check': 'capacity-owner-recovery-udp', 'status': 'pass',
                            'sharedAssociation': True, 'samples': samples, 'settingsUnchanged': True})
            h.result('client.' + case['name'] + '.capacity-owner-recovery-udp', True)
        except Exception as error:
            h.result('client.' + case['name'] + '.capacity-owner-recovery-udp', False, error)
        finally:
            h.stop(proc)
            panel.restart()


def panel_outbound(panel, case, config, folder, scenario):
    exported = outbound_variant(config, scenario, folder)
    template = h.outbound_template([case], {case['name']: exported})
    expected = scenario.get('outboundExpect', 'pass')
    h.require(expected in ('pass', 'deny', 'reject'), 'invalid outbound expectation')
    if expected == 'reject':
        previous = json.loads(panel.api('POST', '/panel/xray/'))['xraySetting']
        previous_pid = h.current_core_pid(panel)
        response = panel.http.post(panel.url + '/panel/xray/update', data={'xraySetting': json.dumps(template),
                                   'outboundTestUrl': f'http://{h.TARGET}:{h.HTTP_PORT}/echo'}, timeout=30)
        response.raise_for_status()
        h.require(not response.json().get('success'), 'invalid outbound unexpectedly saved')
        after = json.loads(panel.api('POST', '/panel/xray/'))['xraySetting']
        h.require(after == previous and h.current_core_pid(panel) == previous_pid, 'rejected outbound changed saved configuration or restarted core')
        h.result('outbound.' + case['name'] + '.expected-rejection-preserves-state', True)
        return
    # Outbound traffic and panel's own test must not use global bypass routes.
    panel.api('POST', '/panel/xray/update', data={'xraySetting': json.dumps(template), 'outboundTestUrl': f'http://{h.TARGET}:{h.HTTP_PORT}/echo'})
    panel.restart()
    h.require(h.wait_port(case['out_socks'], 15), 'panel outbound SOCKS did not listen')
    saved = json.loads(panel.api('POST', '/panel/xray/'))['xraySetting']
    h.require(saved == template, 'outbound settings changed during panel save/readback')
    h.write_json(folder / 'panel-outbound.json', template)
    h.result('outbound.' + case['name'] + '.persistence', True)
    outbounds = [next(o for o in template['outbounds'] if o['tag'] == case['name'] + '-proxy')]
    if case['protocol'] == 'shadowtls':
        outbounds.extend(o for o in template['outbounds'] if o['protocol'] == 'shadowtls' and o not in outbounds)
    def button(phase='panel-test-button', expect_denied=False):
        for outbound in outbounds:
            answer = panel.api('POST', '/panel/xray/testOutbound', data={'outbound': json.dumps(outbound), 'allOutbounds': json.dumps(template['outbounds'])})
            if expect_denied:
                h.require(not answer.get('success'), 'outbound expected denial unexpectedly forwarded traffic')
            else:
                h.require(answer.get('success') and answer.get('statusCode') == 200, 'panel latency probe failed for ' + outbound['protocol'] + ': ' + str(answer.get('error', 'unknown')))
            METRICS.append({'case': case['name'], 'path': phase, 'check': 'session-denial' if expect_denied else 'latency',
                            'protocol': outbound['protocol'], 'status': 'pass', 'milliseconds': answer.get('delay')})
            h.result('outbound.' + case['name'] + '.' + phase + '.' + outbound['protocol'], True)
    if expected == 'deny':
        denied = False
        try:
            http_request(case['out_socks'], timeout=5)
        except (OSError, AssertionError, http.client.HTTPException):
            denied = True
        h.require(denied, 'negative outbound unexpectedly forwarded HTTP')
        button('expected-denial', expect_denied=True)
        h.result('outbound.' + case['name'] + '.expected-traffic-denial', True)
        return
    if case.get('singleSessionCapacity'):
        try:
            button('single-session-allowed')
        except Exception as error:
            h.result('outbound.' + case['name'] + '.single-session-allowed', False, error)
        # DNS/KCP does not have a TCP close signal; clear the finished helper's
        # retained session before measuring the next independent owner.
        panel.restart()
        h.require(h.wait_port(case['out_socks'], 15), 'capacity reset did not start panel outbound')
    run_checks(case, case['out_socks'], 'outbound')
    try:
        if case.get('singleSessionCapacity'):
            button('excess-session-denied', expect_denied=True)
            panel.restart()
            h.require(h.wait_port(case['out_socks'], 15), 'capacity recovery did not start panel outbound')
            button('session-capacity-recovered')
        else:
            button()
    except Exception as error:
        h.result('outbound.' + case['name'] + '.panel-test-button', False, error)
    if case.get('singleFlowCapacity') and case.get('udp', True):
        panel.restart()
        h.require(h.wait_port(case['out_socks'], 15), 'capacity UDP recovery did not start panel outbound')
        try:
            samples = udp_series(case['out_socks'], (32, 512, 1200))
            METRICS.append({'case': case['name'], 'path': 'outbound', 'check': 'capacity-owner-recovery-udp', 'status': 'pass',
                            'sharedAssociation': True, 'samples': samples, 'settingsUnchanged': True})
            h.result('outbound.' + case['name'] + '.capacity-owner-recovery-udp', True)
        except Exception as error:
            h.result('outbound.' + case['name'] + '.capacity-owner-recovery-udp', False, error)


def lifecycle(panel, client_core, case, config, path, folder):
    selected = case['settings']['clients'][0]
    token = 'email:' + base64.urlsafe_b64encode(selected['email'].encode()).decode().rstrip('=')
    update = lambda value: panel.api('POST', '/panel/api/inbounds/updateClient/' + token,
                                    json={'id': case['id'], 'settings': json.dumps({'clients': [value]})})
    update(dict(selected, enable=False))
    panel.restart()
    proc = h.launch([client_core, 'run', '-c', path], folder, folder / 'revoked.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        h.require(h.wait_port(SOCKS, 10), 'negative client did not listen')
        denied = False
        try:
            http_request(SOCKS, timeout=4)
        except (OSError, AssertionError, http.client.HTTPException):
            denied = True
        h.require(denied, 'disabled account still forwarded traffic')
        h.result('lifecycle.' + case['name'] + '.disabled-denied', True)
    finally:
        h.stop(proc)
        update(selected)
        panel.restart()
    n.wait_native_listener(panel, case)
    proc = h.launch([client_core, 'run', '-c', path], folder, folder / 'reenabled.log', dict(os.environ, **{'xray.endpoint.mapping': 'off'}))
    try:
        h.require(h.wait_port(SOCKS, 10), 'restored client did not listen')
        data, _ = http_request(SOCKS)
        h.require(data == h.BODY, 'reenabled account did not recover')
        h.result('lifecycle.' + case['name'] + '.reenabled', True)
    finally:
        h.stop(proc)


def default_cases():
    cases = [{'name': 'generated-' + protocol, 'protocol': protocol} for protocol in ('openvpn', 'anytls', 'shadowtls', 'dnstt', 'mieru')]
    for name in ('openvpn-tcp', 'openvpn-udp', 'openvpn-tcp-proof', 'anytls-normal', 'anytls-custom',
                 'mieru-tcp', 'mieru-udp', 'mieru-tcp-custom', 'dnstt-vless', 'dnstt-socks',
                 'shadowtls-v3', 'shadowtls-custom', 'shadowtls-aead', 'shadowtls-ss2022'):
        cases.append({'name': name, 'base': name, 'protocol': name.split('-')[0], 'udp': name not in ('dnstt-socks', 'shadowtls-aead')})
    return cases


def main(args):
    load_helpers(args.repo.resolve())
    h.require(os.environ.get('D11_HOST_NETNS') and os.readlink('/proc/self/ns/net') != os.environ['D11_HOST_NETNS'], 'private network namespace required')
    routes = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True).strip()
    h.require(not routes, 'private namespace unexpectedly has a default route')
    work = args.work.resolve()
    h.require(not work.exists(), 'work directory must be fresh')
    work.mkdir(parents=True, mode=0o700)
    scenarios = []
    for path in args.manifest:
        value = json.loads(path.read_text())
        if isinstance(value, dict):
            value = value.get('cases', value.get('runtime_cases', value.get('runtime_variants', [])))
        h.require(isinstance(value, list) and value, 'manifest must contain a nonempty scenario array: ' + str(path))
        scenarios.extend(value)
    if not scenarios:
        scenarios = default_cases()
    if args.only:
        selected = set(args.only.split(','))
        scenarios = [case for case in scenarios if case['name'] in selected or case['protocol'] in selected]
    h.require(scenarios, 'no selected scenarios')
    h.require(len({case['name'] for case in scenarios}) == len(scenarios), 'duplicate scenario names')
    for scenario in scenarios:
        if args.ipv6:
            scenario.setdefault('ipv6', True)
        if args.concurrency:
            scenario.setdefault('concurrentStreams', args.concurrency)
        if args.sustain_seconds:
            scenario.setdefault('sustainSeconds', args.sustain_seconds)
        if args.half_close:
            scenario.setdefault('halfClose', True)
    h.write_json(work / 'manifest.json', scenarios)
    binaries = {name: {'path': str(path.resolve()), 'sha256': digest(path)} for name, path in
                (('panel', args.panel), ('serverCore', args.server_core), ('unchangedClientCore', args.client_core))}
    if args.stock_core:
        binaries['stockCore'] = {'path': str(args.stock_core.resolve()), 'sha256': digest(args.stock_core)}
    panel, servers, udp = None, [], None
    completed = 0
    try:
        certificates = h.certificates(work / 'fixtures')
        os.environ['SSL_CERT_FILE'] = str(work / 'fixtures/ca.crt')
        panel = h.Panel(work / 'panel', args.panel.resolve(), args.server_core.resolve(), args.panel_arch)
        panel.init()
        panel.start()
        h.cert_server_secret = certificates['server.key'].splitlines()[1]
        presets = {case['name']: case for case in h.make_cases(panel, certificates, panel.db / 'certs')}
        for index, scenario in enumerate(scenarios):
            folder = work / 'cases' / scenario['name']
            folder.mkdir(parents=True)
            case = None
            try:
                servers, udp = [], []
                targets(work / 'fixtures', scenario.get('coverTLS', '1.3'), scenario.get('ipv6', False), servers, udp)
                case = fixture(panel, scenario, presets, index)
                resolver = dns_resolver_fixture(case, scenario, work / 'fixtures')
                if resolver:
                    servers.append(resolver)
                payload = h.payload(case)
                payload['listen'] = case['listen']
                response = panel.http.post(panel.url + '/panel/api/inbounds/add', json=payload, timeout=90)
                response.raise_for_status()
                answer = response.json()
                if answer.get('success') and isinstance(answer.get('obj'), dict):
                    case['id'] = answer['obj'].get('id')
                if scenario.get('expect') == 'reject':
                    h.require(not answer.get('success'), 'invalid inbound accepted')
                    h.result('api.' + case['name'] + '.expected-rejection', True)
                    completed += 1
                    continue
                h.require(answer.get('success'), 'panel create rejected: ' + str(answer.get('msg', 'unknown')))
                case['id'] = answer['obj']['id']
                config = copied_config(panel, case)
                path = folder / 'copied-client.json'
                h.write_json(path, config)
                if args.stock_core:
                    accepted = parse(args.stock_core.resolve(), path, folder / 'stock-parse.log', expect=None)
                    METRICS.append({'case': case['name'], 'path': 'official-stock-core', 'check': 'parse-only',
                                    'accepted': accepted, 'dnsAliasIsNotTunnelSupport': case['protocol'] == 'dnstt',
                                    'note': 'Stock dns accepts this alias as ordinary DNS, not the native tunnel.' if case['protocol'] == 'dnstt' else ''})
                accepted = parse(args.client_core.resolve(), path, folder / 'client-parse.log', expect=None if scenario.get('expect') == 'deny' else True)
                if not accepted and scenario.get('expect') == 'deny':
                    h.result('client.' + case['name'] + '.expected-parser-denial', True)
                    completed += 1
                    continue
                h.result('api.' + case['name'] + '.create-export-parse', True)
                panel.restart()
                if scenario.get('outboundOnly'):
                    reason = scenario.get('clientSkipReason', 'Explicit server-outbound-only fixture.')
                    METRICS.append({'case': case['name'], 'path': 'client', 'check': 'traffic', 'status': 'not-run', 'reason': reason})
                    print('SKIP client.' + case['name'] + ': ' + reason, flush=True)
                else:
                    copy_traffic(panel, args.client_core.resolve(), case, path, folder, scenario)
                if scenario.get('expect') != 'deny':
                    panel_outbound(panel, case, config, folder, scenario)
                    if scenario.get('lifecycle', args.lifecycle) and not scenario.get('outboundOnly'):
                        lifecycle(panel, args.client_core.resolve(), case, config, path, folder)
                completed += 1
            except Exception as error:
                h.result('scenario.' + scenario['name'], False, error)
                (folder / 'failure.txt').write_text(traceback.format_exc())
            finally:
                for process in reversed(h.PROCESSES):
                    if process is not panel.p:
                        h.stop(process)
                if case and case.get('id'):
                    try:
                        panel.api('POST', '/panel/api/inbounds/del/' + str(case['id']))
                        panel.api('POST', '/panel/xray/update', data={'xraySetting': json.dumps(h.base_template()), 'outboundTestUrl': f'http://{h.TARGET}:{h.HTTP_PORT}/echo'})
                        panel.restart()
                    except Exception as error:
                        h.result('cleanup.' + scenario['name'], False, error)
                        raise
                for server in servers:
                    server.shutdown()
                    server.server_close()
                servers = []
                if udp:
                    close_udp(udp)
                    udp = None
            h.write_json(work / 'progress.json', {'completed': completed, 'total': len(scenarios), 'results': h.RESULTS, 'metrics': METRICS})
    except Exception as error:
        h.result('matrix.completion', False, error)
        (work / 'failure.txt').write_text(traceback.format_exc())
    finally:
        for process in reversed(h.PROCESSES):
            h.stop(process)
        for server in servers:
            server.shutdown()
            server.server_close()
        if udp:
            close_udp(udp)
        unchanged = all(digest(Path(item['path'])) == item['sha256'] for item in binaries.values())
        h.result('binaries.unchanged', unchanged)
        report = {'complete': completed == len(scenarios), 'completedScenarios': completed, 'totalScenarios': len(scenarios),
                  'passed': sum(item['ok'] for item in h.RESULTS), 'failed': sum(not item['ok'] for item in h.RESULTS),
                  'privateNetworkNamespace': True, 'defaultRoute': False, 'clientResponsesRepaired': False,
                  'binaries': binaries, 'results': h.RESULTS, 'metrics': METRICS}
        h.write_json(work / 'results.json', report)
        print('RESULTS ' + str(work / 'results.json'), flush=True)
    return 0 if report['complete'] and not report['failed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('repo', 'panel', 'server-core', 'client-core', 'work'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--manifest', type=Path, action='append', default=[])
    parser.add_argument('--stock-core', type=Path)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--concurrency', type=int, default=0)
    parser.add_argument('--sustain-seconds', type=float, default=0)
    parser.add_argument('--half-close', action='store_true')
    parser.add_argument('--panel-arch', choices=('amd64', 'arm64'), default='amd64')
    parser.add_argument('--only', default='')
    parser.add_argument('--lifecycle', action='store_true')
    parser.add_argument('--netns', action='store_true')
    arguments = parser.parse_args()
    if arguments.netns:
        os.environ['D11_HOST_NETNS'] = os.readlink('/proc/self/ns/net')
        os.execvp('unshare', ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                             *[arg for arg in sys.argv[1:] if arg != '--netns']])
    if not os.environ.get('D11_HOST_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['D11_HOST_NETNS']:
        parser.error('invoke with --netns')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'address', 'add', '198.18.0.1/32', 'dev', 'lo'], check=True)
    subprocess.run(['ip', '-6', 'address', 'add', V6_TARGET + '/128', 'dev', 'lo', 'nodad'], check=True)
    def interrupted(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise InterruptedError('test interrupted: ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main(arguments))
