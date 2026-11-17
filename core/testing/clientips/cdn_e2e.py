#!/usr/bin/env python3
"""End-to-end check of /debug/clientips through a fake CDN.

usage: cdn_e2e.py <xray> [<xray-noclientsample>]

On loopback: a server Xray with three VLESS inbounds the way the owner's CDN
inbounds are (WebSocket, HTTPUpgrade, XHTTP; no TLS, the CDN terminates it)
and a metrics listener; a client Xray with one socks inbound per transport
(XHTTP twice: packet-up via auto, and stream-one); between them a fake CDN
reverse proxy (in this process) that rewrites every HTTP/1.1 request and sets
X-Forwarded-For to the "current client" (any XFF the client sent is dropped),
or sends none. The proxy opens each backend connection from the "current
edge", a loopback source address (127.0.0.2, 127.0.0.3, ...), the way a
CDN's edge servers connect from their own IPs.

Each proxied TCP connection through a socks port is one new VLESS connection.
Per connection a different fake client IP from a few operator ranges and an
edge are set; the payload must echo back intact; afterwards /debug/clientips
must list exactly those IPs, newest last, with "peers" listing exactly the
edge each came from, and recorded must have grown by exactly that many. Connections without the header must record nothing. /debug/vars still
answers. With the second xray (built -tags noclientsample) traffic works the
same and nothing is recorded.
"""
import asyncio, json, os, random, socket, struct, subprocess, sys, tempfile, threading, time, urllib.request

XRAY = os.path.abspath(sys.argv[1])
XRAY_OFF = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else None
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
WORK = tempfile.mkdtemp(prefix="cdne2e.")

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

P = {k: free_port() for k in ["ws", "hu", "xh", "metrics", "cdn_ws", "cdn_hu", "cdn_xh",
                               "s_ws", "s_hu", "s_xh", "s_xh1", "echo"]}

passed = failed = 0
def ok(m):
    global passed; passed += 1; print("ok   " + m, flush=True)
def bad(m):
    global failed; failed += 1; print("FAIL " + m, flush=True)
def check(c, m):
    ok(m) if c else bad(m)

# ---------------- fake CDN reverse proxy ----------------
CURRENT = {"xff": None,       # the X-Forwarded-For value the CDN adds now
           "edge": "127.0.0.2"}  # the source address of new backend connections
SEEN = []                     # (port, method, path, xff) per request
EDGES = ["127.0.0.2", "127.0.0.3", "127.0.0.4"]

async def pipe(r, w):
    try:
        while True:
            b = await r.read(65536)
            if not b:
                break
            w.write(b); await w.drain()
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass

async def cdn_conn(cr, cw, backend):
    try:
        br, bw = await asyncio.open_connection("127.0.0.1", backend, limit=1 << 20,
                                              local_addr=(CURRENT["edge"], 0))
    except Exception:
        cw.close(); return
    down = asyncio.ensure_future(pipe(br, cw))
    try:
        while True:
            try:
                head = await cr.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, ConnectionError):
                break
            lines = head[:-4].split(b"\r\n")
            hdrs = [l for l in lines[1:] if not l.lower().startswith(b"x-forwarded-for:")]
            xff = CURRENT["xff"]
            if xff:
                hdrs.append(b"X-Forwarded-For: " + xff.encode())
            meth, path = lines[0].split(b" ")[:2]
            SEEN.append((backend, meth.decode(), path.decode(), xff))
            bw.write(b"\r\n".join([lines[0]] + hdrs) + b"\r\n\r\n")
            h = {}
            for l in hdrs:
                k, _, v = l.partition(b":")
                h[k.strip().lower()] = v.strip().lower()
            if b"upgrade" in h:
                await pipe(cr, bw); break
            if b"content-length" in h:
                n = int(h[b"content-length"])
                while n:
                    b = await cr.read(min(n, 65536))
                    if not b: raise ConnectionError
                    bw.write(b); n -= len(b)
            elif h.get(b"transfer-encoding") == b"chunked":
                while True:
                    sl = await cr.readline(); bw.write(sl)
                    size = int(sl.split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while True:
                            t = await cr.readline(); bw.write(t)
                            if t in (b"\r\n", b""): break
                        break
                    bw.write(await cr.readexactly(size + 2)); await bw.drain()
            await bw.drain()
    except Exception:
        pass
    finally:
        try: bw.close()
        except Exception: pass
        await down

async def echo_conn(r, w):
    await pipe(r, w)

LOOP = asyncio.new_event_loop()
async def start_servers():
    for name, back in [("cdn_ws", P["ws"]), ("cdn_hu", P["hu"]), ("cdn_xh", P["xh"])]:
        await asyncio.start_server(lambda r, w, b=back: cdn_conn(r, w, b), "127.0.0.1", P[name], limit=1 << 20)
    await asyncio.start_server(echo_conn, "127.0.0.1", P["echo"])
def run_loop():
    asyncio.set_event_loop(LOOP); LOOP.run_until_complete(start_servers()); LOOP.run_forever()
threading.Thread(target=run_loop, daemon=True).start()

# ---------------- Xray configs ----------------
def vless_in(tag, port, stream):
    return {"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": stream}
server = {
    "log": {"loglevel": "warning"},
    "metrics": {"tag": "metrics_out", "listen": "127.0.0.1:%d" % P["metrics"]},
    "inbounds": [
        vless_in("ws", P["ws"], {"network": "ws", "wsSettings": {"path": "/ws"}}),
        vless_in("hu", P["hu"], {"network": "httpupgrade", "httpupgradeSettings": {"path": "/hu"}}),
        vless_in("xh", P["xh"], {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}),
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
}
def vless_out(tag, port, stream):
    return {"tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                                    "users": [{"id": UUID, "encryption": "none"}]}]},
            "streamSettings": stream}
CLIENT_PATHS = {  # socks name -> (outbound, cdn port, stream settings)
    "s_ws": ("ws", "cdn_ws", {"network": "ws", "wsSettings": {"path": "/ws"}}),
    "s_hu": ("hu", "cdn_hu", {"network": "httpupgrade", "httpupgradeSettings": {"path": "/hu"}}),
    "s_xh": ("xh", "cdn_xh", {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}),
    "s_xh1": ("xh1", "cdn_xh", {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "stream-one"}}),
}
client = {
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": s, "listen": "127.0.0.1", "port": P[s], "protocol": "socks",
                  "settings": {"udp": False}} for s in CLIENT_PATHS],
    "outbounds": [vless_out(o, P[c], st) for (o, c, st) in CLIENT_PATHS.values()],
    "routing": {"rules": [{"type": "field", "inboundTag": [s], "outboundTag": o}
                          for s, (o, _, _) in CLIENT_PATHS.items()]},
}

def start_xray(binary, cfg, name):
    path = os.path.join(WORK, name + ".json")
    json.dump(cfg, open(path, "w"))
    log = open(os.path.join(WORK, name + ".log"), "w")
    p = subprocess.Popen([binary, "run", "-c", path], stdout=log, stderr=subprocess.STDOUT)
    return p

def wait_port(port, t=10):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError:
            time.sleep(0.05)
    return False

def get(path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (P["metrics"], path), timeout=5) as r:
        return r.status, r.headers.get("Content-Type"), r.read()

def clientips():
    st, ct, body = get("/debug/clientips")
    return json.loads(body)

def socks_echo(sport, nbytes):
    s = socket.create_connection(("127.0.0.1", P[sport]), 5); s.settimeout(10)
    s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", P["echo"]))
    rep = b""
    while len(rep) < 10: rep += s.recv(10 - len(rep))
    assert rep[1] == 0, "socks reply %r" % rep
    data = os.urandom(nbytes); got = bytearray()
    def sender():
        s.sendall(data)
    th = threading.Thread(target=sender); th.start()
    while len(got) < nbytes:
        b = s.recv(65536)
        if not b: break
        got += b
    th.join(); s.close()
    return bytes(got) == data

RANGES = ["151.232.%d.%d", "5.112.%d.%d", "2.144.%d.%d", "37.129.%d.%d", "2a01:5ec0:%x::%x"]
def fake_ip(i):
    r = RANGES[i % len(RANGES)]
    return r % (random.randint(1, 250), random.randint(1, 250))

def run(binary, recording):
    tag = "on" if recording else "off"
    print("== %s: %s" % (tag, binary), flush=True)
    sp = start_xray(binary, server, "server-" + tag)
    cp = start_xray(XRAY, client, "client-" + tag)
    try:
        check(all(wait_port(P[k]) for k in ["ws", "hu", "xh", "metrics"] + list(CLIENT_PATHS)), "%s: cores up" % tag)
        st, ct, body = get("/debug/clientips")
        j0 = json.loads(body)
        check(st == 200 and ct == "application/json", "%s: /debug/clientips 200 application/json" % tag)
        check(j0 == {"v": 1, "recorded": 0, "ips": [], "peers": []}, "%s: empty at start: %s" % (tag, body.decode()))
        check(body.startswith(b'{"v":1,"recorded":0,"ips":['), "%s: v, recorded and ips come first, as in 11.21" % tag)
        st, _, vars_ = get("/debug/vars")
        check(st == 200 and b'"stats"' in vars_, "%s: /debug/vars unchanged (200, has stats)" % tag)

        expected, expected_peers = [], []
        # with the header: 3 rounds over all four client paths, a new IP each
        i = 0
        for rnd in range(3):
            for s in CLIENT_PATHS:
                ip = fake_ip(i); i += 1
                # one in four as a CDN chain: "client, edge" (first is used)
                CURRENT["xff"] = ip + (", 104.16.%d.1" % i if i % 4 == 0 else "")
                CURRENT["edge"] = EDGES[(i + rnd) % len(EDGES)]
                n = 1 << 20 if rnd == 0 else 4096
                good = socks_echo(s, n)
                check(good, "%s: %s via CDN edge %s with XFF %s: %d bytes echoed"
                      % (tag, s, CURRENT["edge"], CURRENT["xff"], n))
                expected.append(ip)
                expected_peers.append(CURRENT["edge"])
                time.sleep(0.05)
        CURRENT["xff"] = None
        j1 = clientips()
        if recording:
            check(j1["recorded"] == len(expected), "%s: recorded %d == %d connections" % (tag, j1["recorded"], len(expected)))
            check(j1["ips"] == expected, "%s: ips are exactly the forwarded IPs, newest last (%d)" % (tag, len(j1["ips"])))
            if j1["ips"] != expected:
                print("     got      %s\n     expected %s" % (j1["ips"], expected))
            check(j1.get("peers") == expected_peers,
                  "%s: peers are exactly the proxy's edge addresses, same order (%d; %s)"
                  % (tag, len(j1.get("peers") or []), ", ".join("%s=%d" % (e, expected_peers.count(e)) for e in EDGES)))
            if j1.get("peers") != expected_peers:
                print("     got      %s\n     expected %s" % (j1.get("peers"), expected_peers))
        else:
            check(j1 == {"v": 1, "recorded": 0, "ips": [], "peers": []}, "%s: nothing recorded with -tags noclientsample" % tag)

        # without the header: through the CDN (no XFF added) and with a header the CDN strips
        for s in CLIENT_PATHS:
            check(socks_echo(s, 65536), "%s: %s via CDN without XFF: echoed" % (tag, s))
        j2 = clientips()
        check(j2 == j1, "%s: no header -> nothing recorded (recorded stays %d)" % (tag, j1["recorded"]))

        # newest last after more: one more WS with a known IP
        CURRENT["xff"] = "2a01:5ec0:1000::abcd"
        CURRENT["edge"] = "127.0.0.9"
        check(socks_echo("s_ws", 4096), "%s: one more WS (IPv6 XFF, edge 127.0.0.9): echoed" % tag)
        CURRENT["xff"] = None
        CURRENT["edge"] = EDGES[0]
        j3 = clientips()
        if recording:
            check(j3["ips"][-1] == "2a01:5ec0:1000::abcd" and j3["peers"][-1] == "127.0.0.9" and
                  j3["recorded"] == len(expected) + 1,
                  "%s: newest last: %s from %s, recorded %d" % (tag, j3["ips"][-1], j3["peers"][-1], j3["recorded"]))
            check(len(j3["peers"]) == len(j3["ips"]), "%s: peers as long as ips (%d)" % (tag, len(j3["ips"])))
        hdr_seen = sum(1 for x in SEEN if x[3])
        print("     cdn saw %d requests (%d with XFF)" % (len(SEEN), hdr_seen))
        xh_hdr = [x for x in SEEN if x[0] == P["xh"] and x[3]]
        if recording:
            check(len(xh_hdr) > 6, "%s: XHTTP: %d requests (%d GET, %d POST) carried XFF for 6 connections, recorded once each"
                  % (tag, len(xh_hdr), sum(1 for x in xh_hdr if x[1] == "GET"), sum(1 for x in xh_hdr if x[1] == "POST")))
        check(sp.poll() is None and cp.poll() is None, "%s: both cores still running" % tag)
    finally:
        for p in (cp, sp):
            p.terminate()
            try: p.wait(5)
            except Exception: p.kill()
        SEEN.clear()

run(XRAY, True)
if XRAY_OFF:
    run(XRAY_OFF, False)
print("\n%d passed, %d failed" % (passed, failed))
print("logs in", WORK)
sys.exit(1 if failed else 0)
