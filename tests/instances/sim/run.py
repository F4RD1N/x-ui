#!/usr/bin/env python3
"""Run the user simulation against a throwaway copy of the panel.

  sudo python3 run.py single --phases 1:600,2:600,4:600 --out results/
  sudo python3 run.py multi --instances 10 --phases 1:600,2:600,4:600 --out results/
  python3 report.py results/ report.html

Everything runs in three network namespaces of its own, so nothing on the
host (its panel, its xray, its users, its routes) is touched:

  xs-u  the devices (xsim users), on 10.77.1x.0/24 per user network class;
        one veth pair per class to xs-c, with netem for that class's round
        trip and loss, and nft dropping the packets of devices that vanished
  xs-c  a throwaway panel (its own database, the live xray template) and
        its xray cores; the inbound is 10.77.0.1:PORT...
  xs-s  the sites (xsim sites) on 1.2.3.0/24, 1.2.4.0/24, ... per site
        class, one veth pair per class with netem for its distance;
        1.2.9.0/24 is a destination that never answers

The inbound copies the live one (VLESS, TCP with the HTTP header, dialect
4, one client id, no sniffing). single: one core on every --xray-cpus CPU.
multi: --instances cores (the inbound plus sub-inbounds), each on an equal
share of them.

Every 5 s the run records each core's CPU, memory, threads, goroutines and
GC, the busy share of the core, users and sites CPUs, and the core
namespace's sockets and TCP counters. Per phase it writes the users' view
(latency, failures, traffic) next to the server's.

Alongside real users (--real-xui, default /usr/local/x-ui) it also records
the host: free memory, every CPU's busy share, the real panel's cores (CPU,
memory, pids) and, every 30 s, the real inbounds' connections (count,
smoothed RTT, queued data) -- counts and distributions only, no addresses.
A baseline of --baseline seconds is taken before the devices start. The
run stops early (and says why) when free memory falls under --min-mem-gb,
when a real core's pid disappears or changes, or after --max-seconds.
"""
import argparse, glob, json, os, re, resource, shutil, signal, sqlite3, subprocess, sys, threading, time, urllib.parse, urllib.request, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
NS_U, NS_C, NS_S = "xs-u", "xs-c", "xs-s"
SITE_TCP = "443,80,5228,5222,22,8443,2087,853,554"
SITE_UDP = "443,53,3478,50000"
DEAD_NET = "1.2.9"


def sh(cmd, check=True, quiet=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def nsx(ns, cmd, **kw):
    return sh(f"ip netns exec {ns} {cmd}", **kw)


def cpu_list(s):
    out = []
    for part in s.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b) + 1)) if b else [int(a)]
    return out


def fmt_cpus(cpus):
    return ",".join(map(str, cpus))


def cpus_of(spec):
    """a CPU list, or every CPU for 'all'"""
    return list(range(os.cpu_count())) if spec == "all" else cpu_list(spec)


def gen_prefix(cpus, nice):
    """nice and taskset for a generator process; "all" leaves it unpinned"""
    out = []
    if nice:
        out += ["nice", "-n", str(nice)]
    if cpus != "all":
        out += ["taskset", "-c", cpus]
    return out


def raise_nofile(want=2097152):
    """the real panel's unit has LimitNOFILE=2097152; the throwaway panel and
    its cores inherit this process's limit"""
    try:
        want = min(want, int(open("/proc/sys/fs/nr_open").read()))
    except (OSError, ValueError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (want, want))
    except (ValueError, OSError):
        pass
    return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


# ------------------------------------------------------------ network

def teardown_net():
    for ns in (NS_U, NS_C, NS_S):
        pids = sh(f"ip netns pids {ns} 2>/dev/null", check=False).split()
        for p in pids:
            try:
                os.kill(int(p), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        sh(f"ip netns del {ns} 2>/dev/null", check=False)


def setup_net(model):
    teardown_net()
    for ns in (NS_U, NS_C, NS_S):
        sh(f"ip netns add {ns}")
        nsx(ns, "ip link set lo up")
        for k, v in {"net.ipv4.ip_local_port_range": "1024 65535", "net.ipv4.tcp_tw_reuse": "1", "net.core.somaxconn": "65535",
                     "net.ipv4.tcp_max_syn_backlog": "65536", "net.ipv4.tcp_fin_timeout": "15", "net.ipv4.tcp_keepalive_time": "120",
                     "net.ipv4.tcp_rmem": "4096 131072 33554432", "net.ipv4.tcp_wmem": "4096 16384 4194304"}.items():
            nsx(ns, f"sysctl -qw {k}='{v}'", check=False)
    nsx(NS_S, "sysctl -qw net.ipv4.ip_forward=1")
    # the inbound address
    nsx(NS_C, "ip link add in0 type dummy")
    nsx(NS_C, "ip addr add 10.77.0.1/32 dev in0")
    nsx(NS_C, "ip link set in0 up")
    # users: one link per network class
    for i, n in enumerate(model["net"]):
        u, c = f"xu{i}", f"xc{i}"
        sh(f"ip link add {u} netns {NS_U} type veth peer name {c} netns {NS_C}")
        nsx(NS_U, f"ip addr add 10.77.{10 + i}.1/24 dev {u}")
        for h in range(2, 65):
            nsx(NS_U, f"ip addr add 10.77.{10 + i}.{h}/24 dev {u}")
        nsx(NS_C, f"ip addr add 10.77.{100 + i}.1/24 dev {c}")
        for ns, dev in ((NS_U, u), (NS_C, c)):
            nsx(ns, f"ip link set {dev} up")
            half = n["rttMs"] / 2
            nsx(ns, f"tc qdisc add dev {dev} root netem delay {half:g}ms {n['jitterMs'] / 2:g}ms loss {n['lossPct'] / 2:g}% limit 1000000")
        # replies to this class go back over its own link
        nsx(NS_C, f"ip route add 10.77.{10 + i}.0/24 dev {c}")
        nsx(NS_U, f"ip rule add from 10.77.{10 + i}.0/24 lookup {100 + i}")
        nsx(NS_U, f"ip route add 10.77.0.1/32 dev {u} table {100 + i}")
    # vanished devices: their packets are dropped
    nft = """table inet xsim {
  set vanish { type ipv4_addr . inet_service; flags timeout; timeout 30m; size 4000000; }
  chain out { type filter hook output priority 0; policy accept; ip saddr . tcp sport @vanish drop; }
}"""
    p = subprocess.run(["ip", "netns", "exec", NS_U, "nft", "-f", "-"], input=nft, text=True, capture_output=True)
    if p.returncode != 0:
        raise SystemExit("nft: " + p.stderr)
    # sites: one link per site class
    for k, s in enumerate(model["sites"]):
        c, x = f"xs{k}", f"xx{k}"
        sh(f"ip link add {c} netns {NS_C} type veth peer name {x} netns {NS_S}")
        nsx(NS_C, f"ip addr add 10.78.{k}.1/30 dev {c}")
        nsx(NS_S, f"ip addr add 10.78.{k}.2/30 dev {x}")
        for ns, dev in ((NS_C, c), (NS_S, x)):
            nsx(ns, f"ip link set {dev} up")
            nsx(ns, f"tc qdisc add dev {dev} root netem delay {s['rttMs'] / 2:g}ms limit 1000000")
        nsx(NS_C, f"ip route add 1.2.{3 + k}.0/24 via 10.78.{k}.2 dev {c}")
        nsx(NS_S, f"ip route add 10.78.{k}.0/30 dev {x}", check=False)
    nsx(NS_C, f"ip route add {DEAD_NET}.0/24 via 10.78.0.2 dev xs0")
    nsx(NS_S, f"ip route add blackhole {DEAD_NET}.0/24")
    nsx(NS_S, "ip link add st0 type dummy")
    for k in range(len(model["sites"])):
        for h in range(1, 9):
            nsx(NS_S, f"ip addr add 1.2.{3 + k}.{h}/32 dev st0")
    nsx(NS_S, "ip link set st0 up")
    # the sites answer every core-side link
    nsx(NS_S, "ip route add 10.77.0.0/16 via 10.78.0.1 dev xx0", check=False)


def site_spec(model):
    return ";".join(f"{s['name']}=1.2.{3 + k}.1-1.2.{3 + k}.8" for k, s in enumerate(model["sites"]))


def src_spec(model):
    return ";".join(f"{n['name']}=10.77.{10 + i}.1-10.77.{10 + i}.64" for i, n in enumerate(model["net"]))


# ------------------------------------------------------------ panel

class Panel:
    def __init__(self, xui, out, cpus, template, env=None):
        self.xui, self.dir, self.cpus = xui, os.path.join(out, "panel"), cpus
        shutil.rmtree(self.dir, ignore_errors=True)
        for d in ("bin", "db", "log"):
            os.makedirs(os.path.join(self.dir, d))
        for f in ["xray-linux-amd64", "geoip.dat", "geosite.dat"]:
            os.symlink(os.path.join(xui, "bin", f), os.path.join(self.dir, "bin", f))
        self.env = dict(os.environ, XUI_DB_FOLDER=self.dir + "/db", XUI_BIN_FOLDER=self.dir + "/bin", XUI_LOG_FOLDER=self.dir + "/log")
        self.env.update(env or {})
        self.base = "http://127.0.0.1:2053/sim"
        subprocess.run(["ip", "netns", "exec", NS_C, os.path.join(xui, "x-ui"), "setting", "-username", "sim", "-password", "sim",
                        "-port", "2053", "-webBasePath", "/sim/"], env=self.env, check=True, capture_output=True)
        db = sqlite3.connect(self.dir + "/db/x-ui.db")
        db.execute("delete from settings where key='xrayTemplateConfig'")
        db.execute("insert into settings(key, value) values('xrayTemplateConfig', ?)", (open(template).read(),))
        db.commit()
        db.close()
        log = open(self.dir + "/panel.log", "w")
        self.proc = subprocess.Popen(["ip", "netns", "exec", NS_C, "taskset", "-c", fmt_cpus(cpus), os.path.join(xui, "x-ui"), "run"],
                                     env=self.env, cwd=self.dir, stdout=log, stderr=log)
        self.cookie = None
        for _ in range(100):
            try:
                self.login()
                return
            except Exception:
                time.sleep(0.2)
        raise SystemExit("the panel did not come up; see " + self.dir + "/panel.log")

    def req(self, path, data=None):
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(self.base + path, data=body, method="POST" if data is not None else "GET")
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        with urllib.request.urlopen(r, timeout=60) as resp:
            c = resp.headers.get("Set-Cookie")
            if c:
                self.cookie = c.split(";")[0]
            return json.loads(resp.read() or b"{}")

    def login(self):
        res = self.req("/login", {"username": "sim", "password": "sim"})
        if not res.get("success"):
            raise RuntimeError(res)

    def stop(self):
        try:
            self.req("/panel/api/server/stopXrayService", {})
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def xray_pids(self):
        out = {}
        for p in os.listdir("/proc"):
            if not p.isdigit():
                continue
            try:
                cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
                cwd = os.readlink(f"/proc/{p}/cwd")
            except OSError:
                continue
            if len(cmd) >= 3 and cmd[0].endswith(b"xray-linux-amd64") and cwd == self.dir:
                out[os.path.basename(cmd[2].decode())[len("config-"):-len(".json")]] = int(p)
        return out

    def metrics_ports(self):
        out = {}
        for f in glob.glob(self.dir + "/bin/config-*.json"):
            try:
                d = json.load(open(f))
                out[os.path.basename(f)[len("config-"):-len(".json")]] = (d.get("metrics") or {}).get("listen")
            except (OSError, ValueError):
                pass
        return out


def make_inbound(panel, port, cid, cores, instance="xray-1"):
    settings = {"clients": [{"id": cid, "email": "sim", "flow": "", "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True,
                             "tgId": "", "subId": uuid.uuid4().hex[:16], "reset": 0}],
                "decryption": "none", "dialects": [4], "encryption": "none"}
    stream = {"network": "tcp", "security": "none", "externalProxy": [], "tcpSettings": {"acceptProxyProtocol": False, "header": {
        "type": "http", "request": {"version": "1.1", "method": "GET", "path": ["/"], "headers": {}},
        "response": {"version": "1.1", "status": "200", "reason": "OK", "headers": {}}}}}
    sniff = {"enabled": False, "destOverride": ["http", "tls", "quic", "fakedns"], "metadataOnly": False, "routeOnly": False}
    res = panel.req("/panel/api/inbounds/add", {
        "up": 0, "down": 0, "total": 0, "remark": "sim", "enable": "true", "expiryTime": 0, "trafficReset": "never",
        "lastTrafficResetTime": 0, "xrayInstance": instance, "xrayCores": cores, "listen": "", "port": port, "protocol": "vless",
        "settings": json.dumps(settings), "streamSettings": json.dumps(stream), "sniffing": json.dumps(sniff)})
    if not res.get("success"):
        raise SystemExit(f"adding the inbound failed: {res}")
    return res["obj"]["id"]


# ------------------------------------------------------------ sampling

def ticks(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        st = {}
        for line in open(f"/proc/{pid}/status"):
            k, _, v = line.partition(":")
            if k in ("VmRSS", "Threads"):
                st[k] = int(v.split()[0])
        return int(f[11]) + int(f[12]), st
    except (OSError, IndexError, ValueError):
        return None, {}


def cpu_times():
    out = {}
    for line in open("/proc/stat"):
        if not line.startswith("cpu"):
            break
        p = line.split()
        v = list(map(int, p[1:9]))
        out[p[0]] = (sum(v) - v[3] - v[4], v[6], sum(v))
    return out


def ns_proc(pid, name):
    """the core namespace's /proc/net file, read through one of its processes"""
    try:
        return open(f"/proc/{pid}/net/{name}").read()
    except OSError:
        return ""


def snmp_of(pid):
    out = {}
    lines = (ns_proc(pid, "snmp") + ns_proc(pid, "netstat")).splitlines()
    for i in range(0, len(lines) - 1, 2):
        k, v = lines[i].split(), lines[i + 1].split()
        if k and v and k[0] == v[0]:
            for a, b in zip(k[1:], v[1:]):
                try:
                    out[k[0][:-1] + "." + a] = int(b)
                except ValueError:
                    pass
    return out


def sockstat_of(pid):
    out = {}
    for line in (ns_proc(pid, "sockstat") + ns_proc(pid, "sockstat6")).splitlines():
        proto, _, rest = line.partition(":")
        f = rest.split()
        for i in range(0, len(f) - 1, 2):
            try:
                out[f"{proto}.{f[i]}"] = int(f[i + 1])
            except ValueError:
                pass
    return out


def metrics(listen):
    out = {}
    try:
        with urllib.request.urlopen(f"http://{listen}/debug/vars", timeout=10) as r:
            ms = json.loads(r.read()).get("memstats", {})
        out = {k: ms.get(k) for k in ("NumGC", "PauseTotalNs", "HeapInuse", "Sys", "TotalAlloc", "GCCPUFraction")}
        with urllib.request.urlopen(f"http://{listen}/debug/pprof/goroutine?debug=1", timeout=20) as r:
            m = re.match(rb"goroutine profile: total (\d+)", r.read(200))
            if m:
                out["goroutines"] = int(m.group(1))
    except Exception:
        pass
    return out


class Sampler(threading.Thread):
    def __init__(self, panel, groups, extra_pids):
        super().__init__(daemon=True)
        self.panel, self.groups, self.extra = panel, groups, extra_pids
        self.samples, self.stop_flag = [], False

    def run(self):
        hz = os.sysconf("SC_CLK_TCK")
        prev = None
        mports = {}
        while not self.stop_flag:
            now = time.time()
            pids = self.panel.xray_pids()
            if len(mports) < len(pids):
                mports = self.panel.metrics_ports()
            cur = {"t": now, "ticks": {n: ticks(p) for n, p in pids.items()},
                   "extra": {n: ticks(p) for n, p in self.extra.items()}, "cpus": cpu_times()}
            anyp = next(iter(pids.values()), None)
            if anyp:
                cur["snmp"] = snmp_of(anyp)
                cur["sockstat"] = sockstat_of(anyp)
            cur["metrics"] = {n: metrics(l) for n, l in mports.items() if l and n in pids}
            if prev:
                dt = now - prev["t"]
                row = {"t": now, "cores": {}, "extra": {}, "groups": {}}
                for n, (tk, st) in cur["ticks"].items():
                    a = prev["ticks"].get(n, (None, {}))[0]
                    if tk is not None and a is not None:
                        row["cores"][n] = {"cpu": (tk - a) / hz / dt, "rssMB": st.get("VmRSS", 0) / 1024, "threads": st.get("Threads"),
                                           **{k: v for k, v in cur["metrics"].get(n, {}).items()}}
                for n, (tk, st) in cur["extra"].items():
                    a = prev["extra"].get(n, (None, {}))[0]
                    if tk is not None and a is not None:
                        row["extra"][n] = {"cpu": (tk - a) / hz / dt, "rssMB": st.get("VmRSS", 0) / 1024}
                for g, ids in self.groups.items():
                    busy = soft = tot = 0
                    for i in ids:
                        k = f"cpu{i}"
                        if k in cur["cpus"] and k in prev["cpus"]:
                            busy += cur["cpus"][k][0] - prev["cpus"][k][0]
                            soft += cur["cpus"][k][1] - prev["cpus"][k][1]
                            tot += cur["cpus"][k][2] - prev["cpus"][k][2]
                    row["groups"][g] = {"busy": busy / tot if tot else None, "softirq": soft / tot if tot else None}
                if "snmp" in cur and "snmp" in prev:
                    row["tcp"] = {k: (cur["snmp"].get(k, 0) - prev["snmp"].get(k, 0)) / dt for k in (
                        "Tcp.ActiveOpens", "Tcp.PassiveOpens", "Tcp.AttemptFails", "Tcp.InSegs", "Tcp.OutSegs", "Tcp.RetransSegs",
                        "Tcp.EstabResets", "TcpExt.ListenOverflows", "TcpExt.TCPAbortOnTimeout")}
                    row["sockstat"] = cur.get("sockstat")
                self.samples.append(row)
            prev = cur
            time.sleep(max(0, 5 - (time.time() - now)))


def real_ports(xui):
    ports = set()
    for f in glob.glob(os.path.join(xui, "bin", "config-*.json")):
        try:
            for i in json.load(open(f)).get("inbounds", []):
                if i.get("tag") != "api" and i.get("port"):
                    ports.add(int(i["port"]))
        except (OSError, ValueError, TypeError):
            pass
    return sorted(ports)


def real_cores(xui):
    """the real panel's cores: name -> pid (cwd is the panel's directory)"""
    out = {}
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
            cwd = os.readlink(f"/proc/{p}/cwd")
        except OSError:
            continue
        if len(cmd) >= 3 and cmd[0].endswith(b"xray-linux-amd64") and cwd == xui:
            out[os.path.basename(cmd[2].decode())[len("config-"):-len(".json")]] = int(p)
    return out


def meminfo():
    out = {}
    for line in open("/proc/meminfo"):
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            out[k] = int(v.split()[0]) / 1048576  # GiB
    return out


def pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(p * len(vals)))]


def real_sockets(ports):
    """the real inbounds' established connections, seen from the host's
    namespace: count, smoothed RTT and queued data. Nothing else is kept."""
    if not ports:
        return {}
    filt = " or ".join(f"sport = :{p}" for p in ports)
    r = subprocess.run(["nsenter", "--net=/proc/1/ns/net", "ss", "-tniH", "state", "established", f"( {filt} )"],
                       capture_output=True, text=True)
    rtts, sendq = [], []
    for line in r.stdout.splitlines():
        if line[:1] in (" ", "\t"):
            i = line.find(" rtt:")
            if i >= 0:
                try:
                    rtts.append(float(line[i + 5:].split("/", 1)[0]))
                except ValueError:
                    pass
            continue
        f = line.split(None, 2)
        if len(f) >= 2:
            try:
                sendq.append(int(f[1]))
            except ValueError:
                pass
    n = len(sendq)
    return {"conns": n, "srttP50": pct(rtts, .5), "srttP90": pct(rtts, .9), "srttP99": pct(rtts, .99),
            "sendqShare": (sum(1 for q in sendq if q > 0) / n) if n else None, "sendqP90": pct(sendq, .9)}


class HostSampler(threading.Thread):
    """the machine and its real users, next to the simulation"""

    def __init__(self, xui, groups):
        super().__init__(daemon=True)
        self.xui, self.groups = xui, groups
        self.ports = real_ports(xui)
        self.baseline_pids = real_cores(xui)
        self.samples, self.sockets, self.stop_flag = [], [], False
        self.mem_avail = None
        self.pids_changed = None
        threading.Thread(target=self.sock_loop, daemon=True).start()

    def sock_loop(self):
        while not self.stop_flag:
            t = time.time()
            try:
                self.sockets.append({"t": t, **real_sockets(self.ports)})
            except Exception as e:  # keep sampling
                self.sockets.append({"t": t, "error": str(e)})
            time.sleep(max(0, 30 - (time.time() - t)))

    def run(self):
        hz = os.sysconf("SC_CLK_TCK")
        prev = None
        while not self.stop_flag:
            now = time.time()
            pids = real_cores(self.xui)
            if self.baseline_pids and self.pids_changed is None:
                for n, p in self.baseline_pids.items():
                    if pids.get(n) != p:
                        self.pids_changed = f"real core {n}: pid {p} -> {pids.get(n)}"
                        break
            mem = meminfo()
            self.mem_avail = mem.get("MemAvailable")
            cur = {"t": now, "ticks": {n: ticks(p) for n, p in pids.items()}, "cpus": cpu_times(), "sockstat": sockstat_of(1)}
            if prev:
                dt = now - prev["t"]
                row = {"t": now, "memAvailGB": mem.get("MemAvailable"), "memTotalGB": mem.get("MemTotal"), "realCores": {}, "groups": {},
                       "sockstat": cur["sockstat"]}
                for n, (tk, st) in cur["ticks"].items():
                    a = prev["ticks"].get(n, (None, {}))[0]
                    if tk is not None and a is not None:
                        row["realCores"][n] = {"cpu": (tk - a) / hz / dt, "rssMB": st.get("VmRSS", 0) / 1024, "pid": pids[n]}
                for g, ids in self.groups.items():
                    busy = soft = tot = 0
                    for i in ids:
                        k = f"cpu{i}"
                        if k in cur["cpus"] and k in prev["cpus"]:
                            busy += cur["cpus"][k][0] - prev["cpus"][k][0]
                            soft += cur["cpus"][k][1] - prev["cpus"][k][1]
                            tot += cur["cpus"][k][2] - prev["cpus"][k][2]
                    row["groups"][g] = {"busy": busy / tot if tot else None, "softirq": soft / tot if tot else None}
                self.samples.append(row)
            prev = cur
            time.sleep(max(0, 5 - (time.time() - now)))


def summarize_host(host, a, b):
    rows = [r for r in host.samples if a <= r["t"] <= b]
    socks = [r for r in host.sockets if a <= r["t"] <= b and "conns" in r]
    if not rows:
        return {}
    def mean(vals):
        vals = [v for v in vals if v is not None]
        return sum(vals) / len(vals) if vals else None
    names = sorted({n for r in rows for n in r["realCores"]})
    out = {"memAvailGBMin": min(r["memAvailGB"] for r in rows), "memAvailGB": mean([r["memAvailGB"] for r in rows]),
           "realCoreCPU": mean([sum(c["cpu"] for c in r["realCores"].values()) for r in rows]),
           "realCoreRSSGB": mean([sum(c["rssMB"] for c in r["realCores"].values()) / 1024 for r in rows]),
           "realCores": {n: {"cpu": mean([r["realCores"][n]["cpu"] for r in rows if n in r["realCores"]])} for n in names},
           "groups": {g: {k: mean([r["groups"][g][k] for r in rows if g in r["groups"]]) for k in ("busy", "softirq")}
                      for g in rows[0]["groups"]},
           "hostTCP": mean([(r["sockstat"] or {}).get("TCP.inuse") for r in rows])}
    if socks:
        out["real"] = {k: mean([s.get(k) for s in socks]) for k in ("conns", "srttP50", "srttP90", "srttP99", "sendqShare", "sendqP90")}
    return out


def summarize(samples, a, b):
    rows = [r for r in samples if a <= r["t"] <= b]
    if not rows:
        return {}
    def mean(vals):
        vals = [v for v in vals if v is not None]
        return sum(vals) / len(vals) if vals else None
    names = sorted({n for r in rows for n in r["cores"]})
    cores = {}
    for n in names:
        rr = [r["cores"][n] for r in rows if n in r["cores"]]
        cores[n] = {k: mean([x.get(k) for x in rr]) for k in ("cpu", "rssMB", "threads", "goroutines", "HeapInuse")}
        gcs = [x for x in rr if x.get("NumGC") is not None]
        if len(gcs) >= 2:
            span = b - a
            cores[n]["gcPerMin"] = (gcs[-1]["NumGC"] - gcs[0]["NumGC"]) / span * 60
            cores[n]["gcPauseMsPerSec"] = (gcs[-1]["PauseTotalNs"] - gcs[0]["PauseTotalNs"]) / 1e6 / span
            cores[n]["allocMBps"] = (gcs[-1]["TotalAlloc"] - gcs[0]["TotalAlloc"]) / 1e6 / span
    out = {"cores": cores, "coreCPU": sum(c["cpu"] or 0 for c in cores.values()),
           "coreRSSGB": sum(c["rssMB"] or 0 for c in cores.values()) / 1024,
           "goroutines": sum(c["goroutines"] or 0 for c in cores.values()),
           "groups": {g: {k: mean([r["groups"][g][k] for r in rows if g in r["groups"]]) for k in ("busy", "softirq")}
                      for g in rows[0]["groups"]},
           "extra": {n: {k: mean([r["extra"][n][k] for r in rows if n in r["extra"]]) for k in ("cpu", "rssMB")}
                     for n in rows[0]["extra"]}}
    if rows[0].get("tcp"):
        out["tcp"] = {k: mean([r["tcp"][k] for r in rows if r.get("tcp")]) for k in rows[0]["tcp"]}
        out["sockstat"] = {k: mean([(r.get("sockstat") or {}).get(k) for r in rows]) for k in ("TCP.inuse", "TCP6.inuse", "TCP.tw", "TCP.orphan", "UDP.inuse", "UDP6.inuse")}
    return out


# ------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["single", "multi", "setup", "teardown"])
    ap.add_argument("--phases", default="1:600")
    ap.add_argument("--instances", type=int, default=10, help="multi: cores (the inbound plus sub-inbounds)")
    ap.add_argument("--port", type=int, default=20821)
    ap.add_argument("--xray-cpus", default="0-27", help="CPUs for the panel and its cores")
    ap.add_argument("--users-cpus", default="28-41")
    ap.add_argument("--sites-cpus", default="42-55")
    ap.add_argument("--xui", default="/usr/local/x-ui", help="panel install or unpacked release (x-ui and bin/xray)")
    ap.add_argument("--xsim", default=os.path.join(HERE, "xsim"))
    ap.add_argument("--model", default=os.path.join(HERE, "model.json"))
    ap.add_argument("--template", default=os.path.join(HERE, "template.json"))
    ap.add_argument("--ramp", type=float, default=120)
    ap.add_argument("--warm", type=float, default=120)
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--keep", action="store_true", help="keep the namespaces afterwards")
    ap.add_argument("--gen-nice", type=int, default=0, help="nice level for the users and the sites")
    ap.add_argument("--panel-env", default="", help="KEY=VALUE,... for the throwaway panel (e.g. GOGC=150,GOMEMLIMIT=40GiB)")
    ap.add_argument("--real-xui", default="/usr/local/x-ui", help="the real panel, watched alongside")
    ap.add_argument("--baseline", type=float, default=60, help="seconds of the host watched before the devices start")
    ap.add_argument("--min-mem-gb", type=float, default=12, help="stop when free memory falls under this")
    ap.add_argument("--max-seconds", type=float, default=0, help="stop after this long (0 = no limit)")
    ap.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    model = json.load(open(a.model))
    if a.mode == "teardown":
        teardown_net()
        return
    if not a.inner:
        setup_net(model)
        if a.mode == "setup":
            print("namespaces ready:", NS_U, NS_C, NS_S)
            return
        # the rest runs inside the core namespace, where the panel is
        for k in ("xsim", "model", "template", "out", "xui", "real_xui"):
            setattr(a, k, os.path.abspath(getattr(a, k)))
        os.makedirs(a.out, exist_ok=True)
        # what the model asks for at 1x, to set the achieved load against
        fit = subprocess.run(["nice", "-n", "19", a.xsim, "fit", "-model", a.model, "-json", "-measure", "300"],
                             capture_output=True, text=True)
        if fit.returncode == 0:
            open(os.path.join(a.out, "fit1x.json"), "w").write(fit.stdout)
        args = [a.mode, "--inner", "--phases", a.phases, "--instances", str(a.instances), "--port", str(a.port),
                "--xray-cpus", a.xray_cpus, "--users-cpus", a.users_cpus, "--sites-cpus", a.sites_cpus, "--xui", a.xui,
                "--xsim", a.xsim, "--model", a.model, "--template", a.template, "--ramp", str(a.ramp), "--warm", str(a.warm),
                "--out", a.out, "--gen-nice", str(a.gen_nice), "--panel-env", a.panel_env, "--real-xui", a.real_xui,
                "--baseline", str(a.baseline), "--min-mem-gb", str(a.min_mem_gb), "--max-seconds", str(a.max_seconds)] + \
            (["--keep"] if a.keep else [])
        child = subprocess.Popen(["ip", "netns", "exec", NS_C, sys.executable, os.path.abspath(__file__)] + args)
        stop = lambda *_: child.send_signal(signal.SIGTERM)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        rc = child.wait()
        # the namespaces go from here: inside one, ip netns runs in a mount
        # namespace of its own and cannot remove them
        if not a.keep:
            teardown_net()
        sys.exit(rc)
    os.makedirs(a.out, exist_ok=True)
    # a SIGTERM (the outer run, or its time limit) stops the devices like a
    # guard does, so what was measured is kept and everything is cleaned up
    term = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: term.set())
    signal.signal(signal.SIGINT, lambda *_: term.set())
    xcpus = cpu_list(a.xray_cpus)
    run_dir = os.path.join(a.out, a.mode)
    os.makedirs(run_dir, exist_ok=True)
    procs = []
    panel = None
    try:
        nofile = raise_nofile()
        slog = open(os.path.join(run_dir, "sites.log"), "w")
        sites = subprocess.Popen(["ip", "netns", "exec", NS_S] + gen_prefix(a.sites_cpus, a.gen_nice) + [a.xsim, "sites",
                                  "-ips", ",".join(f"1.2.{3 + k}.1-1.2.{3 + k}.8" for k in range(len(model["sites"]))),
                                  "-tcp", SITE_TCP, "-udp", SITE_UDP], stdout=slog, stderr=slog)
        procs.append(sites)
        penv = dict(kv.split("=", 1) for kv in a.panel_env.split(",") if "=" in kv)
        panel = Panel(a.xui, run_dir, xcpus, a.template, penv)
        cid = str(uuid.uuid4())
        if a.mode == "single":
            make_inbound(panel, a.port, cid, len(xcpus))
            ports = [a.port]
        else:
            per = len(xcpus) // a.instances
            if per < 1:
                raise SystemExit("fewer CPUs than instances")
            iid = make_inbound(panel, a.port, cid, per)
            subs = [{"port": a.port + i, "instance": f"xray-{i + 1}", "cores": per, "enable": True} for i in range(1, a.instances)]
            res = panel.req(f"/panel/api/inbounds/{iid}/subInbounds", {"subs": json.dumps(subs)})
            if not res.get("success"):
                raise SystemExit(f"sub-inbounds: {res}")
            ports = [a.port + i for i in range(a.instances)]
        for _ in range(100):
            if len(panel.xray_pids()) >= len(ports):
                break
            time.sleep(0.2)
        time.sleep(3)
        print(f"{a.mode}: cores {sorted(panel.xray_pids())} on CPUs {a.xray_cpus}; nofile {nofile}; panel env {penv}", flush=True)
        # the host and its real users, from before the devices start
        hgroups = {"all": list(range(os.cpu_count())), "xray": xcpus,
                   "rest": [i for i in range(os.cpu_count()) if i not in set(xcpus)]}
        base_from = time.time()
        host = HostSampler(a.real_xui, hgroups)
        host.start()
        print(f"real cores {sorted(host.baseline_pids)}; real inbound ports {host.ports}", flush=True)
        term.wait(a.baseline)
        base_to = time.time()
        ulog = open(os.path.join(run_dir, "users.log"), "w")
        users = subprocess.Popen(["ip", "netns", "exec", NS_U] + gen_prefix(a.users_cpus, a.gen_nice) + [a.xsim, "users",
                                  "-model", a.model, "-inbounds", ",".join(f"10.77.0.1:{p}" for p in ports), "-uuid", cid,
                                  "-dialect", "4", "-src", src_spec(model), "-sites", site_spec(model), "-dead", f"{DEAD_NET}.1-{DEAD_NET}.8",
                                  "-phases", a.phases, "-ramp", str(a.ramp), "-warm", str(a.warm), "-nft",
                                  "-out", os.path.join(run_dir, "users.json")], stdout=subprocess.DEVNULL, stderr=ulog)
        procs.append(users)
        groups = {"xray": xcpus, "users": cpus_of(a.users_cpus), "sites": cpus_of(a.sites_cpus)}
        # the generator's own pids: past "ip netns exec", nice and taskset
        def leaf(p):
            for _ in range(50):
                try:
                    exe = os.readlink(f"/proc/{p.pid}/exe")
                    if exe.endswith("xsim"):
                        return p.pid
                except OSError:
                    pass
                time.sleep(0.1)
            return p.pid
        sampler = Sampler(panel, groups, {"users": leaf(users), "sites": leaf(sites)})
        sampler.start()
        # guards: free memory, the real cores, the time limit
        started, guard = time.time(), None
        while users.poll() is None:
            time.sleep(2)
            if term.is_set():
                guard = "stopped from outside (signal)"
            elif host.mem_avail is not None and host.mem_avail < a.min_mem_gb:
                guard = f"free memory {host.mem_avail:.1f} GiB < {a.min_mem_gb:g} GiB"
            elif host.pids_changed:
                guard = host.pids_changed
            elif a.max_seconds and time.time() - started > a.max_seconds:
                guard = f"time limit {a.max_seconds:g} s"
            if guard:
                print(f"GUARD: {guard} -- stopping the devices", flush=True)
                guard = {"reason": guard, "at": time.time()}
                users.send_signal(signal.SIGTERM)
                try:
                    users.wait(120)
                except subprocess.TimeoutExpired:
                    users.kill()
                break
        sampler.stop_flag = True
        sampler.join(15)
        host.stop_flag = True
        host.join(15)
        try:
            u = json.load(open(os.path.join(run_dir, "users.json")))
        except (OSError, ValueError):
            u = {"phases": []}
        phases = []
        for p in u.get("phases") or []:
            phases.append({"users": p, "server": summarize(sampler.samples, p["measureFromUnix"], p["endUnix"]),
                           "host": summarize_host(host, p["measureFromUnix"], p["endUnix"])})
        fit1x = None
        try:
            fit1x = json.load(open(os.path.join(a.out, "fit1x.json")))
        except (OSError, ValueError):
            pass
        res = {"mode": a.mode, "instances": 1 if a.mode == "single" else a.instances, "xrayCPUs": a.xray_cpus,
               "usersCPUs": a.users_cpus, "sitesCPUs": a.sites_cpus, "genNice": a.gen_nice, "panelEnv": penv,
               "phasesPlanned": a.phases, "modelOnline": model["devices"]["online"], "fit1x": fit1x, "guard": guard,
               "baseline": summarize_host(host, base_from, base_to), "realPorts": host.ports,
               "realPidsBefore": host.baseline_pids, "realPidsAfter": real_cores(a.real_xui),
               "phases": phases, "samples": sampler.samples, "hostSamples": host.samples, "realSockets": host.sockets}
        json.dump(res, open(os.path.join(a.out, f"{a.mode}.json"), "w"), indent=1)
        b = res["baseline"].get("real") or {}
        print(f"baseline: real conns {b.get('conns') or 0:.0f} srtt p50/p90 {b.get('srttP50') or 0:.0f}/{b.get('srttP90') or 0:.0f} ms "
              f"real cores CPU {res['baseline'].get('realCoreCPU') or 0:.1f} mem free {res['baseline'].get('memAvailGB') or 0:.0f} GiB", flush=True)
        for p in phases:
            uu, ss, hh = p["users"], p["server"], p["host"]
            r = hh.get("real") or {}
            print(f"scale {uu['scale']:g}: devices {uu['devices']:.0f} mux {uu['mux']:.0f} sessions {uu['tcpSessions']:.0f}+{uu['udpSessions']:.0f} "
                  f"down {uu['perSec'].get('downBytes', 0) / 1e6:.0f} MB/s | sim cores CPU {ss.get('coreCPU', 0):.2f} real {hh.get('realCoreCPU') or 0:.1f} "
                  f"| box busy {(hh.get('groups', {}).get('all', {}).get('busy') or 0) * 100:.0f}% | "
                  f"TTFB p50/p99 {uu['ttfbMs']['p50']:.0f}/{uu['ttfbMs']['p99']:.0f} ms | failed {uu['totals'].get('sessionsFailed', 0)} | "
                  f"real srtt p50/p90 {r.get('srttP50') or 0:.0f}/{r.get('srttP90') or 0:.0f} | free {hh.get('memAvailGBMin') or 0:.0f} GiB", flush=True)
        if guard:
            print("stopped early:", guard["reason"], flush=True)
        print("wrote", os.path.join(a.out, f"{a.mode}.json"))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        if panel:
            panel.stop()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
