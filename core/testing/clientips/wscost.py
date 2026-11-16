#!/usr/bin/env python3
"""CPU per 1k new VLESS-over-WebSocket connections, recording on vs off.

usage: wscost.py <xray-on> <xray-off> [conns per run] [rounds]

A server Xray (one VLESS WS inbound, freedom out, metrics listener as in the
owner's template) is started fresh per run. Load processes open new
connections straight to the inbound with X-Forwarded-For set (a different
fake IP each); each does the WS upgrade, one VLESS request to a local echo
server with 8 bytes of data, waits for the echo and closes. The server's own
CPU (utime+stime from /proc) is divided by the connections it served. The
two builds alternate, after a warm-up per process.
"""
import asyncio, base64, json, multiprocessing as mp, os, socket, struct, subprocess, sys, tempfile, time, urllib.request, uuid

ON, OFF = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
N = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
ROUNDS = int(sys.argv[4]) if len(sys.argv) > 4 else 3
WORKERS, CONC, WARM = 3, 48, 2000
UID = "b831381d-6324-4d53-ad4f-8cda48b30811"
HZ = os.sysconf("SC_CLK_TCK")
WORK = tempfile.mkdtemp(prefix="wscost.")

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def cpu(pid):
    f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])

def frame(payload):
    mask = os.urandom(4)
    n = len(payload)
    hdr = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xFE]) + struct.pack(">H", n)
    return hdr + mask + bytes(b ^ mask[i & 3] for i, b in enumerate(payload))

async def one(port, echo, i, wid):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    ip = "151.%d.%d.%d" % (232 + wid, (i >> 8) & 255, i & 255)
    key = base64.b64encode(os.urandom(16)).decode()
    w.write(("GET /ws HTTP/1.1\r\nHost: cdn.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Forwarded-For: %s\r\n\r\n" % (key, ip)).encode())
    head = await r.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 101"), head[:40]
    req = (b"\x00" + uuid.UUID(UID).bytes + b"\x00\x01" + struct.pack(">H", echo) + b"\x01"
           + socket.inet_aton("127.0.0.1") + b"pingpong")
    w.write(frame(req))
    got = b""
    while len(got) < 2 + 2 + 8:  # ws header, vless response header, echo
        b = await r.read(4096)
        if not b: raise ConnectionError("closed after %r" % got)
        got += b
    assert got.endswith(b"pingpong"), got
    w.close()
    try: await w.wait_closed()
    except Exception: pass

async def echo_srv(r, w):
    try:
        while True:
            b = await r.read(4096)
            if not b: break
            w.write(b); await w.drain()
    except Exception: pass
    w.close()

def worker(port, echo, count, wid, q):
    async def main():
        sem = asyncio.Semaphore(CONC); errs = 0
        async def run(i):
            nonlocal errs
            async with sem:
                try: await asyncio.wait_for(one(port, echo, i, wid), 10)
                except Exception: errs += 1
        await asyncio.gather(*(run(i) for i in range(count)))
        return errs
    q.put(asyncio.run(main()))

def echo_proc(port, ready):
    async def main():
        await asyncio.start_server(echo_srv, "127.0.0.1", port, backlog=1024)
        ready.set(); await asyncio.Event().wait()
    asyncio.run(main())

def load(port, echo, total):
    q = mp.Queue(); ps = [mp.Process(target=worker, args=(port, echo, total // WORKERS, w, q)) for w in range(WORKERS)]
    for p in ps: p.start()
    errs = sum(q.get() for _ in ps)
    for p in ps: p.join()
    return (total // WORKERS) * WORKERS, errs

def run(binary, label, echo):
    port, mport = free_port(), free_port()
    cfg = {"log": {"loglevel": "error"},
           "metrics": {"tag": "metrics_out", "listen": "127.0.0.1:%d" % mport},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                         "settings": {"clients": [{"id": UID}], "decryption": "none"},
                         "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}],
           "outbounds": [{"protocol": "freedom"}]}
    path = os.path.join(WORK, label + ".json"); json.dump(cfg, open(path, "w"))
    p = subprocess.Popen([binary, "run", "-c", path], stdout=open(path + ".log", "w"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try: socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError: time.sleep(0.05)
    load(port, echo, WARM)
    time.sleep(1)
    c0, t0 = cpu(p.pid), time.time()
    n, errs = load(port, echo, N)
    c1, t1 = cpu(p.pid), time.time()
    body = urllib.request.urlopen("http://127.0.0.1:%d/debug/clientips" % mport, timeout=5).read()
    rec = json.loads(body)["recorded"]
    p.terminate(); p.wait(5)
    ms = (c1 - c0) * 1000 / HZ
    return dict(label=label, conns=n, errs=errs, cpu_ms=ms, per1k=ms / (n / 1000), secs=t1 - t0, recorded=rec,
                load=open("/proc/loadavg").read().split()[0])

if __name__ == "__main__":
    echo = free_port(); ready = mp.Event()
    ep = mp.Process(target=echo_proc, args=(echo, ready), daemon=True); ep.start(); ready.wait(10)
    res = {"on": [], "off": []}
    for r in range(ROUNDS):
        for label, b in (("on", ON), ("off", OFF)) if r % 2 == 0 else (("off", OFF), ("on", ON)):
            x = run(b, "%s-%d" % (label, r), echo)
            res[label].append(x["per1k"])
            print("%-6s %d conns (%d errors) in %.1fs: server CPU %.0f ms = %.1f ms per 1k  recorded=%d  load %s"
                  % (x["label"], x["conns"], x["errs"], x["secs"], x["cpu_ms"], x["per1k"], x["recorded"], x["load"]), flush=True)
    for k in ("on", "off"):
        v = sorted(res[k]); print("%s: per 1k %s  median %.1f ms" % (k, ["%.1f" % y for y in res[k]], v[len(v) // 2]))
    mon, moff = sorted(res["on"])[ROUNDS // 2], sorted(res["off"])[ROUNDS // 2]
    print("on - off: %+.1f ms per 1k (%+.1f%%); spread off %.1f..%.1f, on %.1f..%.1f"
          % (mon - moff, 100 * (mon - moff) / moff, min(res["off"]), max(res["off"]), min(res["on"]), max(res["on"])))
    ep.terminate()
