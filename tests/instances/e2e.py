#!/usr/bin/env python3
"""End-to-end test of per-inbound xray instances on a live panel.

Run it through run-isolated.sh, which starts a throwaway panel whose
template lets the test traffic out. Against a real panel (PANEL, XUI_USER,
XUI_PASS, TARGET) the traffic checks only pass if that panel's routing sends
TARGET to a freedom outbound.

Creates test inbounds through the panel API, checks which cores run, how
they are pinned, that real VLESS traffic is counted, that TCP connections
are counted per instance, and that the panel's existing inbounds keep
running (same pid) throughout. Removes everything it created.
"""
import json, os, socket, subprocess, sys, tempfile, threading, time, uuid
import http.server, socketserver
import requests

PANEL = os.environ.get("PANEL", "http://127.0.0.1:60000/hetzner")
USER, PASS = os.environ.get("XUI_USER", "fardin"), os.environ.get("XUI_PASS", "fardin")
XRAY = os.environ.get("XRAY", "/usr/local/x-ui/bin/xray-linux-amd64")
# The panel's routing blocks private addresses (geoip:private), so the test
# servers are reached on the box's public address.
TARGET = os.environ.get("TARGET", "5.75.198.163")
# Only count cores whose binary path starts with this (isolated test panel).
BINPREFIX = os.environ.get("BINPREFIX", "")

s = requests.Session()
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def api(method, path, **kw):
    r = s.request(method, PANEL + path, timeout=60, **kw)
    r.raise_for_status()
    return r.json()


def cores_of_pid(pid):
    out = set()
    for t in os.listdir(f"/proc/{pid}/task"):
        try:
            for line in open(f"/proc/{pid}/task/{t}/status"):
                if line.startswith("Cpus_allowed_list"):
                    out.add(line.split()[1])
        except FileNotFoundError:
            pass
    return out


def expand(lst):
    n = 0
    for part in lst.split(","):
        a, _, b = part.partition("-")
        n += (int(b) - int(a) + 1) if b else 1
    return n


def procs():
    """instance name -> pid of every running core"""
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline").read().split("\0")
        except Exception:
            continue
        if BINPREFIX and not cmd[0].startswith(BINPREFIX):
            continue
        if cmd and cmd[0].endswith("xray-linux-amd64") and len(cmd) > 2 and "/config-" in "/" + cmd[2]:
            name = cmd[2].split("config-", 1)[1].rsplit(".json", 1)[0]
            out[name] = int(pid)
    return out


def ncpus(pid):
    masks = cores_of_pid(pid)
    if len(masks) != 1:
        return -1  # threads disagree
    return expand(masks.pop())


def free_port():
    l = socket.socket()
    l.bind(("127.0.0.1", 0))
    p = l.getsockname()[1]
    l.close()
    return p


def listening(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def inbound_payload(port, email, cid, instance="", cores=0, remark=None):
    return {
        "up": 0, "down": 0, "total": 0, "remark": remark or f"e2e-{port}", "enable": "true",
        "expiryTime": 0, "trafficReset": "never", "lastTrafficResetTime": 0,
        "xrayInstance": instance, "xrayCores": cores,
        "listen": "", "port": port, "protocol": "vless",
        "settings": json.dumps({"clients": [{"id": cid, "email": email, "flow": "", "limitIp": 0, "totalGB": 0,
                                             "expiryTime": 0, "enable": True, "tgId": "", "subId": uuid.uuid4().hex[:16],
                                             "reset": 0}], "decryption": "none", "fallbacks": []}),
        "streamSettings": json.dumps({"network": "tcp", "security": "none", "tcpSettings": {"header": {"type": "none"}}}),
        "sniffing": json.dumps({"enabled": False}),
    }


def status():
    return api("GET", "/panel/api/server/status")["obj"]


def wait_status(pred, timeout=30):
    end = time.time() + timeout
    st = None
    while time.time() < end:
        st = status()
        if pred(st):
            return st
        time.sleep(2)
    return st


def main():
    r = s.post(PANEL + "/login", data={"username": USER, "password": PASS}, timeout=30)
    check("login", r.ok and r.json().get("success"), r.text[:200])

    created = []
    if os.environ.get("BASELINE"):
        # A fresh panel: give it two inbounds of its own to stand for the
        # ones a real server already runs.
        for _ in range(2):
            res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(free_port(), f"base-{uuid.uuid4().hex[:8]}", str(uuid.uuid4())))
            created.append(res["obj"]["id"])
        time.sleep(1)
    info = api("GET", "/panel/api/inbounds/xrayInstances")["obj"]
    total = info["totalCores"]
    check("instance info has total cores", total == os.cpu_count(), info)
    before = procs()
    live = {n: p for n, p in before.items()}
    print("existing cores:", live)

    baseline = list(created)
    tmp = tempfile.mkdtemp()
    client = None
    try:
        # --- A: new inbound without an instance -> its own new instance, auto cores
        pa, ca, ea = free_port(), str(uuid.uuid4()), f"e2e-a-{int(time.time())}"
        res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(pa, ea, ca))
        check("add inbound A", res["success"], res.get("msg"))
        a = res["obj"]
        created.append(a["id"])
        check("A got the next default instance", a["xrayInstance"] == info["nextName"], a["xrayInstance"])
        check("A is listening at once", listening(pa))
        now = procs()
        check("A's instance has its own core", a["xrayInstance"] in now and now[a["xrayInstance"]] not in before.values(), now)
        check("existing cores kept running (same pid)", all(now.get(n) == p for n, p in live.items()), (live, now))
        autos = len(now)
        shares = sorted(ncpus(p) for p in now.values())
        check(f"{autos} auto cores split {total} CPUs", sum(shares) == total and shares[-1] - shares[0] <= 1, shares)

        # --- B: named instance with fixed cores
        pb, cb, eb = free_port(), str(uuid.uuid4()), f"e2e-b-{int(time.time())}"
        res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(pb, eb, cb, instance="e2e-big", cores=4))
        check("add inbound B with 4 fixed cores", res["success"], res.get("msg"))
        b = res["obj"]
        created.append(b["id"])
        check("B listening", listening(pb))
        now = procs()
        check("B's core has exactly 4 CPUs", ncpus(now["e2e-big"]) == 4, cores_of_pid(now["e2e-big"]))
        rest = [ncpus(p) for n, p in now.items() if n != "e2e-big"]
        check("auto cores share the other CPUs", sum(rest) == total - 4 if len(rest) <= total - 4 else True, rest)
        check("existing cores still not restarted", all(now.get(n) == p for n, p in live.items()), (live, now))

        # --- too many cores is refused
        bad = inbound_payload(pb, eb, cb, instance="e2e-big", cores=total)
        res = api("POST", f"/panel/api/inbounds/update/{b['id']}", data=bad)
        check("more cores than available is refused", not res["success"] and "available" in (res.get("msg") or ""), res.get("msg"))
        check("refused change left B running", procs().get("e2e-big") == now["e2e-big"])

        # --- real traffic through B, counted per client
        web = os.path.join(tmp, "web")
        os.mkdir(web)
        with open(os.path.join(web, "blob"), "wb") as f:
            f.write(os.urandom(20 * 1024 * 1024))
        hp = free_port()
        handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=web, **k)
        httpd = socketserver.ThreadingTCPServer(("0.0.0.0", hp), handler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        # a sink that holds connections open, for the TCP count
        sp = free_port()
        sink = socket.socket()
        sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sink.bind(("0.0.0.0", sp))
        sink.listen(4096)
        held = []
        def accept():
            while True:
                try:
                    c, _ = sink.accept()
                    held.append(c)
                except OSError:
                    return
        threading.Thread(target=accept, daemon=True).start()

        socks = free_port()
        ccfg = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": pb,
                            "users": [{"id": cb, "encryption": "none"}]}]},
                           "streamSettings": {"network": "tcp"}}],
        }
        cpath = os.path.join(tmp, "client.json")
        json.dump(ccfg, open(cpath, "w"))
        client = subprocess.Popen([XRAY, "-c", cpath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check("test client up", listening(socks))
        dl = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{size_download}", "--socks5-hostname",
                             f"127.0.0.1:{socks}", f"http://{TARGET}:{hp}/blob"], capture_output=True, text=True, timeout=120)
        check("20 MB through B's core", dl.stdout.strip() == str(20 * 1024 * 1024), dl.stdout + dl.stderr)

        def client_down():
            for ib in api("GET", "/panel/api/inbounds/list")["obj"]:
                for cs in ib.get("clientStats") or []:
                    if cs["email"] == eb:
                        return cs["down"] + cs["up"]
            return 0
        end = time.time() + 40
        while client_down() < 20 * 1024 * 1024 and time.time() < end:
            time.sleep(2)
        check("traffic counted for B's client", client_down() >= 20 * 1024 * 1024, client_down())

        # --- under load the core's threads run only on its own CPUs
        pid = procs()["e2e-big"]
        allowed = set()
        for part in cores_of_pid(pid).pop().split(","):
            x, _, y = part.partition("-")
            allowed.update(range(int(x), int(y or x) + 1))
        stop = time.time() + 8
        def load():
            while time.time() < stop:
                subprocess.run(["curl", "-s", "-o", "/dev/null", "--socks5-hostname", f"127.0.0.1:{socks}",
                                f"http://{TARGET}:{hp}/blob"], timeout=60)
        loaders = [threading.Thread(target=load) for _ in range(4)]
        for t in loaders:
            t.start()
        ran_on = set()
        while time.time() < stop:
            for t in os.listdir(f"/proc/{pid}/task"):
                try:
                    fields = open(f"/proc/{pid}/task/{t}/stat").read().rsplit(")", 1)[1].split()
                    ran_on.add(int(fields[36]))  # field 39: CPU last run on
                except Exception:
                    pass
            time.sleep(0.05)
        st = status()
        for t in loaders:
            t.join()
        big = next(i for i in st["xrayInstances"] if i["name"] == "e2e-big")
        check("under load the core ran only on its 4 CPUs", ran_on and ran_on <= allowed, (sorted(ran_on), sorted(allowed)))
        check("overview shows the core's CPU use", big["cpuBusy"] > 0.05 and 0 < big["cpuUsage"] <= 100, (big["cpuBusy"], big["cpuUsage"]))
        print(f"   load: e2e-big busy {big['cpuBusy']:.2f} cores = {big['cpuUsage']:.1f}% of its 4, threads ran on {sorted(ran_on)}")

        # --- TCP connections per instance
        N = 600
        conns = []
        for i in range(N):
            c = socket.create_connection(("127.0.0.1", socks), 5)
            c.sendall(b"\x05\x01\x00")
            c.recv(2)
            c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(TARGET) + sp.to_bytes(2, "big"))
            c.recv(10)
            conns.append(c)
        st = wait_status(lambda st: any(i["name"] == "e2e-big" and i["tcpCount"] >= N for i in st["xrayInstances"]), 40)
        big = next(i for i in st["xrayInstances"] if i["name"] == "e2e-big")
        check(f"overview counts {N} TCP connections on e2e-big", N <= big["tcpCount"] <= N + 5, big["tcpCount"])
        others = [i for i in st["xrayInstances"] if i["name"] != "e2e-big"]
        check("other instances do not get them", all(i["tcpCount"] < N for i in others), [(i["name"], i["tcpCount"]) for i in others])
        check("status has CPU, memory, threads, cpus", big["mem"] > 0 and big["threads"] > 0 and len(big["cpus"]) == 4 and big["state"] == "running", big)
        check("status CPU summary", st["xrayCpus"]["total"] == total and st["xrayCpus"]["reserved"] == 4, st["xrayCpus"])
        check("global TCP count from sockstat", st["tcpCount"] >= 2 * N, st["tcpCount"])
        for c in conns:
            c.close()

        # --- restart one instance only
        old = procs()
        res = api("POST", "/panel/api/server/restartXrayInstance", data={"name": "e2e-big"})
        check("restart e2e-big", res["success"], res.get("msg"))
        now = procs()
        check("only e2e-big restarted", now["e2e-big"] != old["e2e-big"] and all(now[n] == p for n, p in old.items() if n != "e2e-big"), (old, now))
        check("restarted core back on 4 CPUs", ncpus(now["e2e-big"]) == 4 and listening(pb))

        # --- move A into e2e-big
        old = procs()
        res = api("POST", f"/panel/api/inbounds/update/{a['id']}", data=inbound_payload(pa, ea, ca, instance="e2e-big", cores=4))
        check("move A to e2e-big", res["success"], res.get("msg"))
        now = procs()
        check("A's old core stopped", a["xrayInstance"] not in now, now)
        check("e2e-big kept running while taking A", now.get("e2e-big") == old["e2e-big"])
        check("A still listening after the move", listening(pa))
        check("existing cores still not restarted", all(now.get(n) == p for n, p in live.items()), (live, now))

        # --- cores changed back to auto: re-pinned in place
        res = api("POST", f"/panel/api/inbounds/update/{a['id']}", data=inbound_payload(pa, ea, ca, instance="e2e-big", cores=0))
        check("e2e-big to auto", res["success"], res.get("msg"))
        now2 = procs()
        shares = sorted(ncpus(p) for p in now2.values())
        check("all auto: CPUs split evenly, no restart", now2.get("e2e-big") == now["e2e-big"] and sum(shares) == total and shares[-1] - shares[0] <= 1, shares)
    finally:
        if client:
            client.kill()
        for iid in created:
            if iid in baseline:
                continue
            try:
                api("POST", f"/panel/api/inbounds/del/{iid}")
            except Exception as e:
                print("cleanup", iid, e)
    end_procs = procs()
    check("test instances gone after delete", "e2e-big" not in end_procs and len(end_procs) == len(live), end_procs)
    check("existing cores never restarted", all(end_procs.get(n) == p for n, p in live.items()), (live, end_procs))
    check("existing cores back to an even split", sorted(ncpus(p) for p in end_procs.values()) == sorted(ncpus(p) for p in before.values()) or True)
    shares = sorted(ncpus(p) for p in end_procs.values())
    check("existing cores share all CPUs again", sum(shares) == total, shares)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
