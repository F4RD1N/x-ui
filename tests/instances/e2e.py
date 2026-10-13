#!/usr/bin/env python3
"""End-to-end test of per-inbound xray instances on a live panel.

Run it through run-isolated.sh, which starts a throwaway panel whose
template lets the test traffic out. Against a real panel (PANEL, XUI_USER,
XUI_PASS, TARGET) the traffic checks only pass if that panel's routing sends
TARGET to a freedom outbound.

Creates test inbounds through the panel API, checks which cores run, how
they are pinned (and that bin/instances.json says so), that real VLESS
traffic is counted, that TCP connections are counted per instance, and that
the panel's existing inbounds keep running (same pid) throughout. Removes
everything it created.

With FAKE_TOPO=1 (run-isolated.sh) the panel sees the fake two-node CPU
topology in XUI_HW_ROOT, and the test checks that instances stay on one node.
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
# The panel's bin folder, where it writes instances.json.
BINDIR = BINPREFIX.rstrip("/") if BINPREFIX else os.path.dirname(XRAY)
FAKE_TOPO = bool(os.environ.get("FAKE_TOPO"))
HWROOT = os.environ.get("XUI_HW_ROOT", "")

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


def cpuset(lst):
    out = set()
    for part in (lst or "").split(","):
        if part.strip():
            a, _, b = part.partition("-")
            out.update(range(int(a), int(b or a) + 1))
    return out


def pinned(pid):
    """the CPUs a core is pinned to, None when its threads disagree"""
    masks = cores_of_pid(pid)
    return cpuset(masks.pop()) if len(masks) == 1 else None


def check_instances_file(label, total):
    """bin/instances.json lists exactly the running cores, each with the
    CPUs it is pinned to, and the panel's CPUs as allowed."""
    end = time.time() + 5
    while True:
        try:
            with open(os.path.join(BINDIR, "instances.json")) as f:
                doc = json.load(f)
        except (OSError, ValueError):
            doc = None
        now = procs()
        listed = {}
        for i in (doc or {}).get("instances", []):
            listed[os.path.basename(i["config"]).split("config-", 1)[1].rsplit(".json", 1)[0]] = cpuset(i["cpus"])
        ok = (doc is not None and doc.get("version") == 1 and len(cpuset(doc.get("allowed"))) == total
              and set(listed) == set(now) and all(listed[n] == pinned(p) for n, p in now.items()))
        if ok or time.time() > end:
            break
        time.sleep(0.2)
    check(f"instances.json lists the running cores on their CPUs ({label})", ok,
          (doc, {n: sorted(pinned(p) or []) for n, p in now.items()}))


def fake_topology():
    """the fake topology's nodes (id -> CPUs) and cores (CPU -> its core's CPUs)"""
    base = os.path.join(HWROOT, "sys/devices/system")
    nodes = {}
    for d in os.listdir(base + "/node"):
        if d.startswith("node") and d[4:].isdigit():
            nodes[int(d[4:])] = cpuset(open(f"{base}/node/{d}/cpulist").read().strip())
    cores = {}
    for c in set().union(*nodes.values()):
        cores[c] = cpuset(open(f"{base}/cpu/cpu{c}/topology/core_cpus_list").read().strip())
    return nodes, cores


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


def quiet_port(span=12):
    """A port below the ephemeral range with the next span ports free too,
    so copies on port+1, port+2, ... do not run into client connections."""
    import random
    for _ in range(500):
        p = random.randint(20000, 30000)
        if all(free(p + i) for i in range(span)):
            return p
    return free_port()


def free_port():
    l = socket.socket()
    l.bind(("127.0.0.1", 0))
    p = l.getsockname()[1]
    l.close()
    return p


def free(port):
    try:
        l = socket.socket()
        l.bind(("0.0.0.0", port))
        l.close()
        return True
    except OSError:
        return False


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
            res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(quiet_port(), f"base-{uuid.uuid4().hex[:8]}", str(uuid.uuid4())))
            created.append(res["obj"]["id"])
        time.sleep(1)
    info = api("GET", "/panel/api/inbounds/xrayInstances")["obj"]
    total = info["totalCores"]
    check("instance info has total cores", total == os.cpu_count(), info)
    before = procs()
    live = {n: p for n, p in before.items()}
    print("existing cores:", live)
    check_instances_file("existing cores", total)
    if FAKE_TOPO:
        nodes, cores = fake_topology()
        print("fake topology: nodes", {n: sorted(c) for n, c in nodes.items()})
        if len(before) == 2:
            sets = [pinned(p) for p in before.values()]
            check("two auto cores each on one fake node of their own",
                  all(c and any(c <= n for n in nodes.values()) for c in sets) and not (sets[0] & sets[1]),
                  [sorted(c or []) for c in sets])

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
        check_instances_file("after A", total)

        # --- B: named instance with fixed cores
        pb, cb, eb = free_port(), str(uuid.uuid4()), f"e2e-b-{int(time.time())}"
        res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(pb, eb, cb, instance="e2e-big", cores=4))
        check("add inbound B with 4 fixed cores", res["success"], res.get("msg"))
        b = res["obj"]
        created.append(b["id"])
        check("B listening", listening(pb))
        now = procs()
        check("B's core has exactly 4 CPUs", ncpus(now["e2e-big"]) == 4, cores_of_pid(now["e2e-big"]))
        check_instances_file("after B", total)
        if FAKE_TOPO:
            big = pinned(now["e2e-big"]) or set()
            whole = any(big <= n for n in nodes.values()) and all(cores[c] <= big for c in big)
            if any(len(n) == 4 for n in nodes.values()):
                whole = big in nodes.values()
            check("B's 4 fixed CPUs are whole cores of one fake node", whole, sorted(big))
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

        # --- Multi Instance: sub-inbounds -- the same inbound on the next ports
        pc = quiet_port(4)
        cc, ec = str(uuid.uuid4()), f"e2e-c-{int(time.time())}"
        res = api("POST", "/panel/api/inbounds/add", data=inbound_payload(pc, ec, cc))
        c = res["obj"]
        created.append(c["id"])
        n_inbounds = len(api("GET", "/panel/api/inbounds/list")["obj"])
        plan = api("POST", f"/panel/api/inbounds/{c['id']}/multiInstance", data={"count": 2, "cores": 1, "max": "false", "subs": "[]"})["obj"]
        check("sub-inbound plan: the next ports, new instances", plan and not plan["error"] and [i["port"] for i in plan["items"]] == [pc + 1, pc + 2], plan)
        mx = api("POST", f"/panel/api/inbounds/{c['id']}/multiInstance", data={"count": 0, "cores": 1, "max": "true", "subs": "[]"})["obj"]
        check("Max fills the free cores", mx["max"] == mx["available"] and mx["count"] == mx["max"], mx)
        subs = [{"port": i["port"], "instance": i["instance"], "cores": 1, "enable": True} for i in plan["items"]]
        old = procs()
        res = api("POST", f"/panel/api/inbounds/{c['id']}/subInbounds", data={"subs": json.dumps(subs)})
        check("save sub-inbounds", res["success"], res.get("msg"))
        check("still one inbound, no copies", len(api("GET", "/panel/api/inbounds/list")["obj"]) == n_inbounds)
        now = procs()
        check("each sub-inbound runs in its own core on 1 CPU", all(s["instance"] in now and ncpus(now[s["instance"]]) == 1 for s in subs), now)
        check("sub-inbounds did not restart running cores", all(now.get(n) == p for n, p in old.items()), (old, now))
        check("sub-inbounds listening", listening(pc + 1) and listening(pc + 2))
        # A client added after the sub-inbounds exist reaches them too, with
        # the same email and the same traffic total.
        dc, ed = str(uuid.uuid4()), f"e2e-d-{int(time.time())}"
        res = api("POST", "/panel/api/inbounds/addClient", data={"id": c["id"], "settings": json.dumps({"clients": [{
            "id": dc, "email": ed, "flow": "", "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True,
            "tgId": "", "subId": uuid.uuid4().hex[:16], "reset": 0}]})})
        check("add a client to the inbound", res["success"], res.get("msg"))
        check("adding the client restarted no core", procs() == now, (now, procs()))
        socks2 = free_port()
        ccfg2 = dict(ccfg)
        ccfg2["inbounds"] = [{"listen": "127.0.0.1", "port": socks2, "protocol": "socks", "settings": {"udp": False}}]
        ccfg2["outbounds"] = [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": pc + 2, "users": [{"id": dc, "encryption": "none"}]}]}, "streamSettings": {"network": "tcp"}}]
        cpath2 = os.path.join(tmp, "client2.json")
        json.dump(ccfg2, open(cpath2, "w"))
        client2 = subprocess.Popen([XRAY, "-c", cpath2], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            listening(socks2)
            dl = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{size_download}", "--socks5-hostname",
                                 f"127.0.0.1:{socks2}", f"http://{TARGET}:{hp}/blob"], capture_output=True, text=True, timeout=120)
            check("the new client works on a sub-inbound port", dl.stdout.strip() == str(20 * 1024 * 1024), dl.stdout)
            def client_traffic(email):
                for ib in api("GET", "/panel/api/inbounds/list")["obj"]:
                    for cs in ib.get("clientStats") or []:
                        if cs["email"] == email:
                            return cs["up"] + cs["down"]
                return 0
            end = time.time() + 40
            while client_traffic(ed) < 20 * 1024 * 1024 and time.time() < end:
                time.sleep(2)
            check("its traffic counts on its one email", client_traffic(ed) >= 20 * 1024 * 1024, client_traffic(ed))
            def inbound_traffic():
                ib = next(i for i in api("GET", "/panel/api/inbounds/list")["obj"] if i["id"] == c["id"])
                return ib["up"] + ib["down"]
            # The core's inbound counter leaves out the first chunk of a
            # response (written with the protocol's response header): the
            # headers, and some body when it arrives with them. Allow one
            # buffer.
            want = 20 * 1024 * 1024 - 16 * 1024
            end = time.time() + 30
            while inbound_traffic() < want and time.time() < end:
                time.sleep(2)
            check("the sub-inbound's traffic counts on the inbound", inbound_traffic() >= want, inbound_traffic())
        finally:
            client2.kill()
        # Disable one sub-inbound: only its core stops.
        subs[0]["enable"] = False
        pre = procs()
        res = api("POST", f"/panel/api/inbounds/{c['id']}/subInbounds", data={"subs": json.dumps(subs)})
        now = procs()
        check("disabling a sub-inbound stops only its core", res["success"] and subs[0]["instance"] not in now and now.get(subs[1]["instance"]) == pre.get(subs[1]["instance"]), now)
        clash = api("POST", "/panel/api/inbounds/add", data=inbound_payload(pc + 2, f"e2e-x-{int(time.time())}", str(uuid.uuid4())))
        check("another inbound cannot take a sub-inbound's port", not clash["success"], clash.get("msg"))
        if clash.get("success"):
            created.append(clash["obj"]["id"])
        api("POST", f"/panel/api/inbounds/del/{c['id']}")
        created.remove(c["id"])
        check("deleting the inbound stops its sub-inbounds", subs[1]["instance"] not in procs() and not listening(pc + 2, 2))

        # --- restart one instance only
        old = procs()
        res = api("POST", "/panel/api/server/restartXrayInstance", data={"name": "e2e-big"})
        check("restart e2e-big", res["success"], res.get("msg"))
        now = procs()
        check("only e2e-big restarted", now["e2e-big"] != old["e2e-big"] and all(now[n] == p for n, p in old.items() if n != "e2e-big"), (old, now))
        check("restarted core back on 4 CPUs", ncpus(now["e2e-big"]) == 4 and listening(pb))

        # --- stop and start one instance
        old = procs()
        res = api("POST", "/panel/api/server/stopXrayInstance", data={"name": "e2e-big"})
        check("stop e2e-big", res["success"], res.get("msg"))
        now = procs()
        check("only e2e-big stopped", "e2e-big" not in now and all(now.get(n) == p for n, p in old.items() if n != "e2e-big"), now)
        check("its port is closed", not listening(pb, 2))
        st = status()
        big = next(i for i in st["xrayInstances"] if i["name"] == "e2e-big")
        check("overview shows it stopped", big["state"] == "stop", big["state"])
        time.sleep(3)  # the crash check runs every second: it must leave it stopped
        check("the crash check leaves it stopped", "e2e-big" not in procs())
        check_instances_file("e2e-big stopped", total)
        res = api("POST", "/panel/api/server/startXrayInstance", data={"name": "e2e-big"})
        check("start e2e-big", res["success"], res.get("msg"))
        now = procs()
        check("e2e-big back on its 4 CPUs, listening", "e2e-big" in now and ncpus(now["e2e-big"]) == 4 and listening(pb))
        check_instances_file("e2e-big started", total)

        # --- outgoing IP: refused unless it is the server's and reaches out
        addrs = api("GET", "/panel/api/server/hostAddresses")["obj"]
        check("host addresses list the server's address", any(a["ip"] == TARGET for a in addrs), addrs)
        old = procs()
        res = api("POST", "/panel/api/server/setXrayInstanceEgress", data={"name": "e2e-big", "ip": "198.51.100.7"})
        check("an address not on the server is refused", not res["success"] and "not an address of this server" in res.get("msg", ""), res.get("msg"))
        res = api("POST", "/panel/api/server/setXrayInstanceEgress", data={"name": "e2e-big", "ip": TARGET})
        check("an address that reaches nothing is refused", not res["success"] and "answers" in res.get("msg", ""), res.get("msg"))
        res = api("POST", "/panel/api/server/setXrayInstanceEgress", data={"name": "e2e-big", "ip": ""})
        check("server default is accepted", res["success"], res.get("msg"))
        check("refused or unchanged outgoing IPs restart nothing", procs() == old, (old, procs()))
        big = next(i for i in status()["xrayInstances"] if i["name"] == "e2e-big")
        check("overview shows the outgoing IP and UDP ports", big["egress"] == "" and big["udpPorts"] >= 0 and big["udpPool"] > 1000, big)

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
    shares = sorted(ncpus(p) for p in end_procs.values())
    check("existing cores share all CPUs again", sum(shares) == total, shares)
    check_instances_file("at the end", total)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
