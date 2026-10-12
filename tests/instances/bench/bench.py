#!/usr/bin/env python3
"""Compare one xray core with several under many TCP connections.

Runs on the server, next to the panel:

  bench.py setup            delete every inbound, create the bench inbounds
  bench.py run MODE CONNS   MODE is single or multi; writes results/MODE-CONNS.json
  bench.py report           summary table of everything in results/

single = one inbound (port BASE) in one instance with CORES fixed cores.
multi  = Multi Instance copies of it on BASE+1..BASE+COPIES, each in its own
         instance with CORES/COPIES fixed cores.
Both modes get the same CPUs; the load generator and echo server run on
other CPUs (taskset).
"""
import json, os, re, ssl, subprocess, sys, threading, time, urllib.parse, uuid
import http.cookiejar, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
ENV = os.environ.get("BENCH_ENV", os.path.join(HERE, "bench.env"))
BASE = int(os.environ.get("BENCH_PORT", "31000"))
CORES = int(os.environ.get("BENCH_CORES", "16"))
COPIES = int(os.environ.get("BENCH_COPIES", "8"))
CLIENTS = int(os.environ.get("BENCH_CLIENTS", "1000"))
TARGET = os.environ.get("BENCH_TARGET", "76.164.201.34")
ECHO_PORTS = "41001-41016"
CLIENT_CPUS = os.environ.get("BENCH_CLIENT_CPUS", "16-21,44-49")
ECHO_CPUS = os.environ.get("BENCH_ECHO_CPUS", "22-27,50-55")
PHASES = os.environ.get("BENCH_PHASES", "idle:0:30,light:10s:60,medium:5s:60,heavy:2s:60")
XLOAD = os.path.join(HERE, "xload")
HZ = os.sysconf("SC_CLK_TCK")


def env():
    out = {}
    for line in open(ENV):
        k, _, v = line.strip().partition("=")
        out[k] = v.strip().strip('"')
    return out


class Panel:
    def __init__(self):
        e = env()
        # The panel URL on this box (its own certificate, so not verified).
        self.base = os.environ.get("BENCH_PANEL", "https://127.0.0.1:2026/zet/")
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                              urllib.request.HTTPSHandler(context=ctx))
        r = self.post("login", {"username": e["XUI_USERNAME"], "password": e["XUI_PASSWORD"]})
        if not r.get("success"):
            sys.exit("login failed: " + str(r))

    def req(self, method, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        rq = urllib.request.Request(self.base + path, data=body, method=method)
        with self.op.open(rq, timeout=300) as r:
            return json.loads(r.read() or b"{}")

    def post(self, path, data=None):
        return self.req("POST", path, data or {})

    def get(self, path):
        return self.req("GET", path)


STREAM = {
    "network": "tcp", "security": "none", "externalProxy": [],
    "tcpSettings": {"acceptProxyProtocol": False, "header": {
        "type": "http",
        "request": {"version": "1.1", "method": "GET", "path": ["/"], "headers": {}},
        "response": {"version": "1.1", "status": "200", "reason": "OK", "headers": {}}}},
}


def setup():
    p = Panel()
    # The inbound list only shows the logged-in user's inbounds; the
    # instance list shows every inbound.
    for inst in p.get("panel/api/inbounds/xrayInstances")["obj"]["instances"] or []:
        for ib in inst["inbounds"]:
            r = p.post(f"panel/api/inbounds/del/{ib['id']}")
            print("deleted inbound", ib["id"], ib["remark"], ib["port"], r.get("success"))
    ids = [str(uuid.uuid4()) for _ in range(CLIENTS)]
    clients = [{"id": i, "flow": "", "email": f"bench-{n:04d}", "limitIp": 0, "totalGB": 0, "expiryTime": 0,
                "enable": True, "tgId": "", "subId": uuid.uuid4().hex[:16], "comment": "", "reset": 0}
               for n, i in enumerate(ids)]
    r = p.post("panel/api/inbounds/add", {
        "up": 0, "down": 0, "total": 0, "remark": "bench", "enable": "true", "expiryTime": 0,
        "trafficReset": "never", "lastTrafficResetTime": 0, "listen": "", "port": BASE, "protocol": "vless",
        "xrayInstance": "bench-s", "xrayCores": CORES,
        "settings": json.dumps({"clients": clients, "decryption": "none", "encryption": "none"}),
        "streamSettings": json.dumps(STREAM), "sniffing": json.dumps({"enabled": False}),
    })
    if not r.get("success"):
        sys.exit("create bench inbound: " + str(r.get("msg")))
    src = r["obj"]
    r = p.post(f"panel/api/inbounds/{src['id']}/multiInstance",
               {"count": COPIES, "cores": CORES // COPIES, "max": "false", "dryRun": "false"})
    if not r.get("success"):
        sys.exit("multi instance: " + str(r.get("msg")))
    print("created bench inbound", src["id"], "port", BASE, "and", COPIES, "copies")
    open(os.path.join(HERE, "uuids.txt"), "w").write("\n".join(ids) + "\n")


def instances():
    """name -> (pid, metrics port) of every running core"""
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline").read().split("\0")
        except OSError:
            continue
        if len(cmd) > 2 and cmd[0].endswith("xray-linux-amd64") and "config-" in cmd[2]:
            name = cmd[2].split("config-", 1)[1].rsplit(".json", 1)[0]
            cfg = json.load(open(os.path.join("/usr/local/x-ui", cmd[2])))
            listen = (cfg.get("metrics") or {}).get("listen", "")
            out[name] = (int(pid), int(listen.rsplit(":", 1)[1]) if ":" in listen else 0)
    return out


def bench_names(mode, panel):
    names, single = set(), None
    for inst in panel.get("panel/api/inbounds/xrayInstances")["obj"]["instances"]:
        for ib in inst["inbounds"]:
            if ib["port"] == BASE:
                single = inst["name"]
            elif BASE < ib["port"] <= BASE + COPIES:
                names.add(inst["name"])
    return ([single], sorted(names)) if mode == "single" else (sorted(names), [single])


def switch(mode, panel):
    want, other = bench_names(mode, panel)
    for n in other:
        panel.post("panel/api/server/stopXrayInstance", {"name": n})
    for n in want:
        r = panel.post("panel/api/server/startXrayInstance", {"name": n})
        if not r.get("success"):
            # already running: restart it so every run starts from a fresh core
            panel.post("panel/api/server/restartXrayInstance", {"name": n})
    time.sleep(3)
    run = instances()
    missing = [n for n in want if n not in run]
    if missing:
        sys.exit(f"{mode}: not running: {missing}")
    for n in other:
        if n in run:
            sys.exit(f"{mode}: {n} should be stopped")
    return want


def cpu_list(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("Cpus_allowed_list"):
            return line.split()[1]
    return ""


def expand(lst):
    out = []
    for part in lst.split(","):
        a, _, b = part.partition("-")
        out.extend(range(int(a), int(b or a) + 1))
    return out


def proc_ticks(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        rss = int(open(f"/proc/{pid}/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        return int(f[11]) + int(f[12]), rss, int(f[17])
    except (OSError, IndexError, ValueError):
        return None


def cpu_times():
    out = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            vals = list(map(int, f[1:]))
            idle = vals[3] + vals[4]
            out[int(f[0][3:])] = (sum(vals[:8]), idle)
    return out


def tcp_inuse():
    for line in open("/proc/net/sockstat"):
        if line.startswith("TCP:"):
            f = line.split()
            return int(f[2])
    return 0


def gc_stats(port):
    if not port:
        return None
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/debug/vars", timeout=10) as r:
            m = json.loads(r.read())["memstats"]
        return {"numGC": m["NumGC"], "pauseNs": m["PauseTotalNs"], "heapAlloc": m["HeapAlloc"],
                "heapSys": m["HeapSys"], "gcCPU": m["GCCPUFraction"]}
    except Exception:
        return None


class Monitor(threading.Thread):
    def __init__(self, pids, gen_pids, cpus):
        super().__init__(daemon=True)
        self.pids, self.gen_pids, self.cpus = pids, gen_pids, cpus
        self.samples, self.stop = [], threading.Event()

    def run(self):
        last = None
        while not self.stop.is_set():
            now = time.time()
            procs = {p: proc_ticks(p) for p in self.pids + self.gen_pids}
            ct = cpu_times()
            if last:
                dt = now - last[0]
                core = sum((procs[p][0] - last[1][p][0]) for p in self.pids if procs[p] and last[1].get(p)) / HZ / dt
                gen = sum((procs[p][0] - last[1][p][0]) for p in self.gen_pids if procs[p] and last[1].get(p)) / HZ / dt
                busy = []
                for c in self.cpus:
                    t, i = ct[c][0] - last[2][c][0], ct[c][1] - last[2][c][1]
                    busy.append(0 if t <= 0 else 100 * (t - i) / t)
                alltot = sum(ct[c][0] - last[2][c][0] for c in ct)
                allidle = sum(ct[c][1] - last[2][c][1] for c in ct)
                self.samples.append({
                    "t": now, "coreCPU": core, "genCPU": gen,
                    "benchCPUsBusy": sum(busy) / len(busy), "benchCPUsMax": max(busy),
                    "machineBusy": 100 * (alltot - allidle) / alltot if alltot else 0,
                    "rss": sum(procs[p][1] for p in self.pids if procs[p]),
                    "threads": sum(procs[p][2] for p in self.pids if procs[p]),
                    "tcp": tcp_inuse(),
                })
            last = (now, procs, ct)
            self.stop.wait(1.0)


def window(samples, a, b):
    s = [x for x in samples if a <= x["t"] <= b]
    if not s:
        return {}
    avg = lambda k: sum(x[k] for x in s) / len(s)
    return {"coreCPU": avg("coreCPU"), "coreCPUmax": max(x["coreCPU"] for x in s), "genCPU": avg("genCPU"),
            "benchCPUsBusy": avg("benchCPUsBusy"), "benchCPUsMax": max(x["benchCPUsMax"] for x in s),
            "machineBusy": avg("machineBusy"), "rssGB": max(x["rss"] for x in s) / 2**30,
            "threads": max(x["threads"] for x in s), "tcp": max(x["tcp"] for x in s), "samples": len(s)}


def ensure_echo():
    out = subprocess.run(["pgrep", "-f", "xload echo"], capture_output=True, text=True).stdout.split()
    if out:
        return [int(x) for x in out]
    subprocess.Popen(["taskset", "-c", ECHO_CPUS, XLOAD, "echo", "-ports", ECHO_PORTS],
                     stdout=open(os.path.join(HERE, "echo.log"), "a"), stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(1)
    return [int(x) for x in subprocess.run(["pgrep", "-f", "xload echo"], capture_output=True, text=True).stdout.split()]


def drain(timeout=120):
    """Wait for the previous run's sockets to go away."""
    end = time.time() + timeout
    base = None
    while time.time() < end:
        n = tcp_inuse()
        if n < 5000:
            return n
        time.sleep(2)
    return tcp_inuse()


def run(mode, conns, profile=False):
    os.makedirs(RESULTS, exist_ok=True)
    panel = Panel()
    names = switch(mode, panel)
    echo = ensure_echo()
    drain()
    inst = instances()
    pids = [inst[n][0] for n in names]
    cpus = sorted({c for p in pids for c in expand(cpu_list(p))})
    ports = str(BASE) if mode == "single" else f"{BASE + 1}-{BASE + COPIES}"
    print(f"{mode} {conns}: cores {names} on CPUs {cpus}", flush=True)
    mon = Monitor(pids, echo, cpus)
    mon.start()
    gc0 = {n: gc_stats(inst[n][1]) for n in names}
    out_file = os.path.join(RESULTS, f"{mode}-{conns}.client.json")
    t_start = time.time()
    client = subprocess.Popen(
        ["taskset", "-c", CLIENT_CPUS, XLOAD, "client", "-inbound-ports", ports, "-dst-ips", "127.0.0.1-127.0.0.64",
         "-uuids", os.path.join(HERE, "uuids.txt"), "-target", TARGET, "-target-ports", ECHO_PORTS,
         "-conns", str(conns), "-dial-rate", "20000", "-phases", PHASES, "-out", out_file],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    mon.gen_pids = echo + [client.pid]
    gc_marks = {}
    prof = None
    for line in client.stderr:
        line = line.rstrip()
        print("   ", line, flush=True)
        if line.startswith("phase "):
            ph = json.loads(line[6:])
            gc_marks[ph["name"]] = {n: gc_stats(inst[n][1]) for n in names}
        if profile and prof is None and "phase=2" in line:
            # CPU profile of one core in the third phase
            prof = threading.Thread(target=lambda: subprocess.run(
                ["curl", "-s", "-o", os.path.join(RESULTS, f"{mode}-{conns}.cpu.pprof"),
                 f"http://127.0.0.1:{inst[names[0]][1]}/debug/pprof/profile?seconds=20"]), daemon=True)
            prof.start()
    client.wait()
    mon.stop.set()
    mon.join()
    if prof:
        prof.join(timeout=60)
    res = json.load(open(out_file))
    prev = gc0
    for ph in res["phases"]:
        ph["server"] = window(mon.samples, ph["measureFromUnix"], ph["endUnix"])
        cur = gc_marks.get(ph["name"], {})
        n_gc = sum((cur[n] or {}).get("numGC", 0) - (prev.get(n) or {}).get("numGC", 0) for n in names if cur.get(n) and prev.get(n))
        pause = sum((cur[n] or {}).get("pauseNs", 0) - (prev.get(n) or {}).get("pauseNs", 0) for n in names if cur.get(n) and prev.get(n))
        heap = sum((cur[n] or {}).get("heapAlloc", 0) for n in names if cur.get(n))
        ph["server"]["gcRuns"] = n_gc
        ph["server"]["gcPauseMs"] = pause / 1e6
        ph["server"]["heapGB"] = heap / 2**30
        prev = cur
    res["mode"], res["cores"], res["instances"] = mode, len(cpus), names
    res["ramp"] = window(mon.samples, t_start, t_start + res["rampSec"])
    json.dump(res, open(os.path.join(RESULTS, f"{mode}-{conns}.json"), "w"), indent=2)
    json.dump(mon.samples, open(os.path.join(RESULTS, f"{mode}-{conns}.samples.json"), "w"))
    print(json.dumps({"mode": mode, "conns": conns, "established": res["established"], "phases": [
        {k: ph[k] for k in ("name", "recvPerSec", "timeouts", "errors")} | {"p99": ph["rttMs"]["p99"], "coreCPU": round(ph["server"].get("coreCPU", 0), 2)}
        for ph in res["phases"]]}, indent=1), flush=True)


def report():
    rows = []
    for f in sorted(os.listdir(RESULTS)):
        if re.match(r"^(single|multi)-\d+\.json$", f):
            r = json.load(open(os.path.join(RESULTS, f)))
            for ph in r["phases"]:
                s = ph["server"]
                rows.append((r["conns"], ph["name"], r["mode"], r["established"], ph["recvPerSec"], ph["rttMs"]["p50"],
                             ph["rttMs"]["p99"], ph["rttMs"]["p999"], ph["timeouts"] + ph["errors"],
                             s.get("coreCPU", 0), 100 * s.get("coreCPU", 0) / max(1, r["cores"]), s.get("benchCPUsBusy", 0),
                             s.get("rssGB", 0), s.get("gcRuns", 0), s.get("gcPauseMs", 0), s.get("genCPU", 0)))
    order = ["idle", "light", "medium", "heavy"]
    rows.sort(key=lambda x: (x[0], order.index(x[1]) if x[1] in order else 9, x[2]))
    hdr = ("conns", "phase", "mode", "estab", "msg/s", "p50ms", "p99ms", "p999ms", "lost", "cores used", "%of16", "cpus busy%", "RSS GB", "GCs", "GC pause ms", "gen cores")
    print(" | ".join(hdr))
    for r in rows:
        print(" | ".join(f"{v:.1f}" if isinstance(v, float) else str(v) for v in r))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        setup()
    elif cmd == "run":
        run(sys.argv[2], int(sys.argv[3]), profile="--profile" in sys.argv)
    elif cmd == "report":
        report()
    else:
        sys.exit(__doc__)
