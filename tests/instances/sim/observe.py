#!/usr/bin/env python3
"""Watch a live x-ui server and record how its users and xray cores behave,
as the input for the load simulation (sim/model.py turns it into a model).

  observe.py SECONDS OUTDIR

Read-only: it reads ss, /proc, the cores' metrics endpoints and the panel
database (opened read-only). It never stores an address: client and
destination IPs are only used in memory to tell connections apart, and the
output holds counts and distributions.

Output: OUTDIR/observe.json, plus a CPU and a heap profile of the busiest
core (OUTDIR/cpu-<core>.pb.gz, heap-<core>.pb.gz). OUTDIR/done marks the end.
"""
import collections, glob, json, os, re, sqlite3, subprocess, sys, time, urllib.request

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 300
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else "/root/xui-sim/obs"
BIN = "/usr/local/x-ui/bin"
DB = "/etc/x-ui/x-ui.db"
HZ = os.sysconf("SC_CLK_TCK")
FAST, DEEP, PROC, STATES = 2.0, 30.0, 5.0, 60.0


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def q(vals, ps=(0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 0.999)):
    """quantiles of vals as {p: v}, plus n, mean, max"""
    v = sorted(vals)
    if not v:
        return {"n": 0}
    out = {"n": len(v), "mean": sum(v) / len(v), "max": v[-1]}
    for p in ps:
        out["p%g" % (p * 100)] = v[min(len(v) - 1, int(p * len(v)))]
    return out


def hist(vals, edges):
    """counts of vals in [edges[i], edges[i+1]); the last bin is open"""
    c = [0] * len(edges)
    for x in vals:
        i = 0
        while i + 1 < len(edges) and x >= edges[i + 1]:
            i += 1
        c[i] += 1
    return {"edges": edges, "counts": c}


def port_of(addr):
    return int(addr.rsplit(":", 1)[1])


def host_of(addr):
    return addr.rsplit(":", 1)[0]


# ---------------------------------------------------------------- the cores
def cores():
    out = {}
    for f in glob.glob(BIN + "/config-*.json"):
        name = os.path.basename(f)[len("config-"):-len(".json")]
        try:
            d = json.load(open(f))
        except Exception:
            continue
        ins = [i for i in d.get("inbounds", []) if i.get("tag") != "api"]
        out[name] = {
            "ports": [i["port"] for i in ins],
            "metrics": (d.get("metrics") or {}).get("listen"),
            "inbounds": [{"protocol": i.get("protocol"), "network": (i.get("streamSettings") or {}).get("network"),
                          "security": (i.get("streamSettings") or {}).get("security"),
                          "header": (((i.get("streamSettings") or {}).get("tcpSettings") or {}).get("header") or {}).get("type"),
                          "dialects": (i.get("settings") or {}).get("dialects"),
                          "clients": len((i.get("settings") or {}).get("clients") or []),
                          "sniffing": ((i.get("sniffing") or {}).get("enabled"))} for i in ins],
            "policy": d.get("policy"),
            "outbounds": [{"protocol": o.get("protocol"), "tag": o.get("tag"), "sockopt": (o.get("streamSettings") or {}).get("sockopt"),
                           "settings": {k: v for k, v in (o.get("settings") or {}).items() if k in ("domainStrategy",)}} for o in d.get("outbounds", [])],
        }
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
        if len(cmd) >= 3 and cmd[0].endswith(b"xray-linux-amd64") and cmd[1] == b"-c":
            name = os.path.basename(cmd[2].decode())[len("config-"):-len(".json")]
            if name in out:
                out[name]["pid"] = int(pid)
                try:
                    for line in open(f"/proc/{pid}/status"):
                        if line.startswith("Cpus_allowed_list:"):
                            out[name]["cpus"] = line.split(":", 1)[1].strip()
                except OSError:
                    pass
    return {k: v for k, v in out.items() if "pid" in v}


def cpu_list(s):
    out = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def proc_stat(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        ticks = int(f[11]) + int(f[12])  # utime + stime
        st = {}
        for line in open(f"/proc/{pid}/status"):
            k, _, v = line.partition(":")
            if k in ("VmRSS", "Threads", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
                st[k] = int(v.split()[0])
        return ticks, st
    except (OSError, IndexError, ValueError):
        return None, {}


def cpu_times():
    """per-CPU (busy, softirq, total) jiffies, plus 'all'"""
    out = {}
    for line in open("/proc/stat"):
        if not line.startswith("cpu"):
            break
        p = line.split()
        v = list(map(int, p[1:9]))
        user, nice, system, idle, iowait, irq, softirq, steal = v
        total = sum(v)
        out[p[0]] = (total - idle - iowait, softirq, total)
    return out


def snmp():
    out = {}
    lines = open("/proc/net/snmp").read().splitlines() + open("/proc/net/netstat").read().splitlines()
    for i in range(0, len(lines) - 1, 2):
        k = lines[i].split()
        v = lines[i + 1].split()
        if k[0] != v[0]:
            continue
        for a, b in zip(k[1:], v[1:]):
            try:
                out[k[0][:-1] + "." + a] = int(b)
            except ValueError:
                pass
    try:
        for line in open("/proc/net/snmp6"):
            k, v = line.split()
            out["Ip6." + k] = int(v)
    except OSError:
        pass
    return out


def netdev():
    out = {}
    for line in open("/proc/net/dev").read().splitlines()[2:]:
        name, rest = line.split(":", 1)
        f = rest.split()
        out[name.strip()] = {"rx_bytes": int(f[0]), "rx_packets": int(f[1]), "tx_bytes": int(f[8]), "tx_packets": int(f[9])}
    return out


def http(url, timeout=30):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        return None


def metrics(c):
    if not c.get("metrics"):
        return {}
    raw = http(f"http://{c['metrics']}/debug/vars", 10)
    out = {}
    if raw:
        try:
            ms = json.loads(raw).get("memstats", {})
            out = {k: ms.get(k) for k in ("NumGC", "PauseTotalNs", "HeapAlloc", "HeapInuse", "HeapSys", "HeapObjects", "Sys",
                                          "NextGC", "GCCPUFraction", "TotalAlloc", "Mallocs", "Frees", "StackInuse")}
        except ValueError:
            pass
    g = http(f"http://{c['metrics']}/debug/pprof/goroutine?debug=1", 20)
    if g:
        m = re.match(rb"goroutine profile: total (\d+)", g)
        if m:
            out["goroutines"] = int(m.group(1))
    return out


def goroutine_stacks(c, top=40):
    """goroutines grouped by stack (function names only), most common first"""
    g = http(f"http://{c['metrics']}/debug/pprof/goroutine?debug=1", 30)
    if not g:
        return []
    out = []
    for block in g.decode(errors="replace").split("\n\n")[1:]:
        lines = block.strip().splitlines()
        if not lines:
            continue
        m = re.match(r"(\d+) @", lines[0])
        if not m:
            continue
        funcs = []
        for line in lines[1:]:
            mm = re.match(r"#\s+0x[0-9a-f]+\s+(\S+)", line)
            if mm:
                fn = re.sub(r"^github\.com/xtls/xray-core/", "", mm.group(1))
                fn = re.sub(r"\+0x[0-9a-f]+$", "", fn)
                funcs.append(fn)
        out.append({"count": int(m.group(1)), "stack": funcs[:10]})
    out.sort(key=lambda x: -x["count"])
    return out[:top]


# ---------------------------------------------------------------- sockets
# tcp_info fields kept from `ss -i`, parsed by splitting key:value tokens
INFO_INT = {"bytes_acked", "bytes_received", "segs_out", "segs_in", "data_segs_out", "data_segs_in",
            "lastsnd", "lastrcv", "lastack", "cwnd", "mss", "rcv_space"}
OUT_SAMPLE = 30  # percent of outgoing sockets given the tcp_info pass


def parse_info(line, e):
    for tok in line.split():
        k, sep, v = tok.partition(":")
        if not sep:
            continue
        try:
            if k in INFO_INT:
                e[k] = int(v)
            elif k == "rtt":
                e["rtt"] = float(v.split("/")[0])
            elif k == "minrtt":
                e["minrtt"] = float(v)
            elif k == "retrans":
                e["retrans"] = int(v.split("/")[1])
            elif k == "busy":
                e["busy"] = int(v.rstrip("ms"))
        except (ValueError, IndexError):
            pass


def listening():
    ports = set()
    for line in sh("ss -tlnH").splitlines():
        p = line.split()
        if len(p) >= 4:
            try:
                ports.add(port_of(p[3]))
            except ValueError:
                pass
    return ports


def established(inports, listen, info=False):
    """{key: entry} for client connections to the cores (inb) and outgoing
    connections (out); key = (local, peer). With info, entries carry tcp_info
    fields and the queues."""
    s = sh("ss -tnH" + ("i" if info else "") + " state established")
    inb, out = {}, {}
    last = None
    for line in s.splitlines():
        if line[:1] in (" ", "\t"):
            if last is not None and info:
                parse_info(line, last)
            continue
        p = line.split()
        if len(p) < 4:
            last = None
            continue
        l, r = p[2], p[3]
        try:
            lp = port_of(l)
        except ValueError:
            last = None
            continue
        e = {"recvq": int(p[0]), "sendq": int(p[1])} if info else {}
        if lp in inports:
            inb[(lp, r)] = e
            last = e
        elif lp in listen:
            last = None  # some other service's client (ssh, panel, ...)
        else:
            out[(l, r)] = e
            # a fixed share of outgoing sockets gets tcp_info, the same ones
            # every time
            last = e if hash((l, r)) % 100 < OUT_SAMPLE else None
            if info and last is None:
                e["skip"] = True
    return inb, out


def udp_sockets():
    s = sh("ss -uanH")
    total, connected = 0, 0
    dports = collections.Counter()
    for line in s.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        total += 1
        peer = p[4]
        if not peer.endswith(":*"):
            connected += 1
            try:
                dports[port_of(peer)] += 1
            except ValueError:
                pass
    return total, connected, dports


def states():
    c = collections.Counter()
    for line in sh("ss -tanH").splitlines():
        p = line.split(None, 1)
        if p:
            c[p[0]] += 1
    return dict(c)


def panel_traffic():
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)
        rows = con.execute("select id, up, down, enable from inbounds").fetchall()
        con.close()
        return {r[0]: {"up": r[1], "down": r[2], "enable": r[3]} for r in rows}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------- main
def main():
    os.makedirs(OUTDIR, exist_ok=True)
    try:
        os.remove(os.path.join(OUTDIR, "done"))
    except OSError:
        pass
    C = cores()
    inports = {p: n for n, c in C.items() for p in c["ports"]}
    listen = listening()
    t0 = time.time()
    res = {"started": t0, "duration": DUR, "nproc": os.cpu_count(), "hz": HZ,
           "cores": {n: {k: v for k, v in c.items()} for n, c in C.items()},
           "sysctl": {k: open("/proc/sys/" + k.replace(".", "/")).read().strip() for k in (
               "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_time", "net.ipv4.ip_local_port_range",
               "net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog", "net.ipv4.tcp_tw_reuse", "net.ipv4.tcp_mem",
               "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc",
               "fs.file-nr") if os.path.exists("/proc/sys/" + k.replace(".", "/"))}}
    res["metrics_start"] = {n: metrics(c) for n, c in C.items()}
    res["panel_start"] = panel_traffic()

    # time series
    series = collections.defaultdict(list)
    first_seen = {}
    initial_in, initial_out = None, None
    life_in, life_out = [], []          # lifetimes of connections born and gone inside the window
    death_init_in, death_init_out = [], []  # when connections already there at t0 went away
    births_in = collections.Counter()   # per second
    births_out = collections.Counter()
    births_port = collections.Counter()
    prev_in, prev_out = None, None
    ips_seen = set()
    ips_t0 = None
    per_ip_samples = []
    deep_prev = {}
    deep = collections.defaultdict(list)
    proc_prev, cpu_prev, snmp_prev, dev_prev = None, None, None, None
    snmp_first, dev_first, snmp_t0 = None, None, None
    next_deep, next_proc, next_states = t0, t0, t0
    profiled = False
    out_dports, out_hosts, out_v6 = collections.Counter(), set(), 0
    udp = []
    busiest = None

    while True:
        now = time.time()
        t = now - t0
        if t > DUR:
            break
        do_deep = now >= next_deep
        inb, outg = established(inports, listen, info=do_deep)

        # births and deaths
        if prev_in is None:
            initial_in, initial_out = set(inb), set(outg)
            for k in inb:
                first_seen[k] = None
            ips_t0 = {host_of(k[1]) for k in inb}
            for k in outg:
                out_dports[port_of(k[1])] += 1
                h = host_of(k[1])
                out_hosts.add(h)
                if ":" in h.strip("[]") and not h.startswith("[::ffff:"):
                    out_v6 += 1
        else:
            sec = int(t)
            for k in inb.keys() - prev_in.keys():
                first_seen[k] = t
                births_in[sec] += 1
                births_port[k[0]] += 1
            for k in prev_in.keys() - inb.keys():
                if k in initial_in:
                    death_init_in.append(t)
                elif first_seen.get(k) is not None:
                    life_in.append(t - first_seen[k])
                first_seen.pop(k, None)
            for k in outg.keys() - prev_out.keys():
                first_seen[k] = t
                births_out[sec] += 1
            for k in prev_out.keys() - outg.keys():
                if k in initial_out:
                    death_init_out.append(t)
                elif first_seen.get(k) is not None:
                    life_out.append(t - first_seen[k])
                first_seen.pop(k, None)
        for k in inb:
            ips_seen.add(host_of(k[1]))
        series["t"].append(round(t, 1))
        series["loop_s"].append(round(time.time() - now, 2))
        series["in"].append(len(inb))
        series["out"].append(len(outg))
        prev_in, prev_out = inb, outg

        # tcp_info: rates over the last DEEP seconds, idle times, RTT, queues
        if do_deep:
            next_deep += DEEP
            per_ip = collections.Counter(host_of(k[1]) for k in inb)
            per_ip_samples.append(sorted(per_ip.values()))
            for side, d in (("in", inb), ("out", outg)):
                rows = []
                for k, e in d.items():
                    if e.get("skip"):
                        continue
                    p = deep_prev.get((side, k))
                    row = {"rtt": e.get("rtt"), "minrtt": e.get("minrtt"), "lastsnd": e.get("lastsnd"), "lastrcv": e.get("lastrcv"),
                           "acked": e.get("bytes_acked", 0), "recv": e.get("bytes_received", 0), "sendq": e["sendq"], "recvq": e["recvq"],
                           "retrans": e.get("retrans", 0), "segs_out": e.get("segs_out", 0), "segs_in": e.get("segs_in", 0),
                           "dsegs_in": e.get("data_segs_in", 0), "dsegs_out": e.get("data_segs_out", 0)}
                    if p is not None:
                        dt = now - p["at"]
                        row["d_acked"] = max(0, row["acked"] - p["acked"]) / dt
                        row["d_recv"] = max(0, row["recv"] - p["recv"]) / dt
                        row["d_segs_in"] = max(0, row["dsegs_in"] - p["dsegs_in"]) / dt
                        row["d_segs_out"] = max(0, row["dsegs_out"] - p["dsegs_out"]) / dt
                        row["d_retrans"] = max(0, row["retrans"] - p["retrans"]) / dt
                    rows.append(row)
                    deep_prev[(side, k)] = {"at": now, **row}
                deep[side].append(rows)
            # forget connections that are gone
            live = {("in", k) for k in inb} | {("out", k) for k in outg}
            for k in list(deep_prev):
                if k not in live:
                    del deep_prev[k]
            ut, uc, ud = udp_sockets()
            udp.append({"t": t, "total": ut, "connected": uc, "dports": ud.most_common(15)})

        # cores' CPU, memory, threads; per-CPU busy; kernel counters
        if now >= next_proc:
            next_proc += PROC
            cur = {n: proc_stat(c["pid"]) for n, c in C.items()}
            cpus = cpu_times()
            sn = snmp()
            dv = netdev()
            if snmp_first is None:
                snmp_first, dev_first, snmp_t0 = sn, dv, now
            if proc_prev is not None:
                dt = now - proc_prev[0]
                row = {"t": round(t, 1)}
                for n in C:
                    a, b = proc_prev[1].get(n, (None, {}))[0], cur[n][0]
                    if a is not None and b is not None:
                        row[n] = {"cpu": (b - a) / HZ / dt, **cur[n][1]}
                groups = {}
                for n, c in C.items():
                    groups[n] = cpu_list(c.get("cpus", ""))
                pinned = {i for g in groups.values() for i in g}
                groups["_free"] = [i for i in range(os.cpu_count()) if i not in pinned]
                for g, ids in groups.items():
                    busy = soft = tot = 0
                    for i in ids:
                        k = f"cpu{i}"
                        if k in cpus and k in cpu_prev:
                            busy += cpus[k][0] - cpu_prev[k][0]
                            soft += cpus[k][1] - cpu_prev[k][1]
                            tot += cpus[k][2] - cpu_prev[k][2]
                    row.setdefault("_cpus", {})[g] = {"busy": busy / tot if tot else None, "softirq": soft / tot if tot else None, "n": len(ids)}
                a = cpus["cpu"]
                b = cpu_prev["cpu"]
                row["_all"] = {"busy": (a[0] - b[0]) / (a[2] - b[2]), "softirq": (a[1] - b[1]) / (a[2] - b[2])}
                row["_snmp"] = {k: (sn.get(k, 0) - snmp_prev.get(k, 0)) / dt for k in (
                    "Tcp.ActiveOpens", "Tcp.PassiveOpens", "Tcp.AttemptFails", "Tcp.EstabResets", "Tcp.InSegs", "Tcp.OutSegs",
                    "Tcp.RetransSegs", "Tcp.OutRsts", "Udp.InDatagrams", "Udp.OutDatagrams", "Ip6.Udp6InDatagrams", "Ip6.Udp6OutDatagrams",
                    "TcpExt.ListenOverflows", "TcpExt.TCPTimeouts", "TcpExt.TCPAbortOnTimeout", "TcpExt.TCPAbortOnClose",
                    "TcpExt.TCPAbortOnData", "TcpExt.TCPAbortOnLinger", "TcpExt.TCPAbortOnMemory", "TcpExt.TW", "TcpExt.TCPFastOpenActive")}
                row["_dev"] = {n: {k: (v[k] - dev_prev[n][k]) / dt for k in v} for n, v in dv.items() if n in dev_prev and v["rx_bytes"] > 0}
                series["proc"].append(row)
                busiest = max(C, key=lambda n: row.get(n, {}).get("cpu", 0))
            proc_prev, cpu_prev, snmp_prev, dev_prev = (now, cur), cpus, sn, dv

        if now >= next_states:
            next_states += STATES
            series["states"].append({"t": round(t, 1), **states()})

        # a CPU profile of the busiest core, a third of the way in
        if not profiled and t > DUR / 3 and busiest:
            profiled = True
            c = C[busiest]
            import threading

            def prof(name=busiest, c=c):
                p = http(f"http://{c['metrics']}/debug/pprof/profile?seconds=15", 60)
                if p:
                    open(os.path.join(OUTDIR, f"cpu-{name}.pb.gz"), "wb").write(p)
                h = http(f"http://{c['metrics']}/debug/pprof/heap", 60)
                if h:
                    open(os.path.join(OUTDIR, f"heap-{name}.pb.gz"), "wb").write(h)
                res["goroutine_stacks"] = {"core": name, "stacks": goroutine_stacks(c)}
            threading.Thread(target=prof, daemon=True).start()

        time.sleep(max(0.0, FAST - (time.time() - now)))

    t_end = time.time()
    span = t_end - t0
    res["ended"] = t_end
    res["metrics_end"] = {n: metrics(c) for n, c in C.items()}
    res["panel_end"] = panel_traffic()
    snmp_last, dev_last = snmp(), netdev()
    sp = t_end - snmp_t0
    res["kernel_rates"] = {k: (snmp_last.get(k, 0) - snmp_first.get(k, 0)) / sp for k in snmp_last
                           if (snmp_last.get(k, 0) - snmp_first.get(k, 0)) != 0}
    res["dev_rates"] = {n: {k: (dev_last[n][k] - dev_first[n][k]) / sp for k in dev_last[n]} for n in dev_last if n in dev_first}

    # connections
    def arrivals(c):
        return {"per_s": sum(c.values()) / span, "total": sum(c.values())}
    res["conns"] = {
        "series": {k: v for k, v in series.items() if k in ("t", "in", "out")},
        "loop_s": q(series["loop_s"]), "out_info_sample_pct": OUT_SAMPLE,
        "in_now": q(series["in"]), "out_now": q(series["out"]),
        "arrivals_in": arrivals(births_in), "arrivals_out": arrivals(births_out),
        "arrivals_by_port": {p: n / span for p, n in births_port.items()},
        "lifetime_in": q(life_in) | {"hist": hist(life_in, [0, 2, 5, 10, 20, 30, 60, 120, 180, 240])},
        "lifetime_out": q(life_out) | {"hist": hist(life_out, [0, 2, 5, 10, 20, 30, 60, 120, 180, 240])},
        "initial_in": len(initial_in), "initial_out": len(initial_out),
        "initial_in_gone_at": hist(death_init_in, [0, 10, 30, 60, 120, 180, 240]),
        "initial_out_gone_at": hist(death_init_out, [0, 10, 30, 60, 120, 180, 240]),
        "born_still_open_in": sum(1 for k, v in first_seen.items() if v is not None and k in prev_in),
        "born_still_open_out": sum(1 for k, v in first_seen.items() if v is not None and k in prev_out),
        "client_ips_at_start": len(ips_t0), "client_ips_seen": len(ips_seen),
        "conns_per_ip": q([x for s in per_ip_samples for x in s]),
        "conns_per_ip_hist": hist([x for s in per_ip_samples[-1:] for x in s], [1, 2, 3, 5, 10, 20, 50, 100]),
        "out_dports": out_dports.most_common(25), "out_unique_hosts": len(out_hosts), "out_ipv6": out_v6,
    }

    # traffic and idleness from tcp_info
    def summarize(rows_list, side):
        last = rows_list[-1]
        allrows = [r for rows in rows_list for r in rows]
        withd = [r for r in allrows if "d_acked" in r]
        down = [r["d_acked"] for r in withd]   # bytes/s the server sent on this socket
        up = [r["d_recv"] for r in withd]      # bytes/s it received
        tot = [a + b for a, b in zip(down, up)]
        active = [x for x in tot if x >= 100]
        totals = sorted(tot, reverse=True)
        s = sum(totals) or 1
        top1 = sum(totals[:max(1, len(totals) // 100)]) / s
        top10 = sum(totals[:max(1, len(totals) // 10)]) / s
        idle = [min(r["lastsnd"] or 0, r["lastrcv"] or 0) / 1000 for r in last if r.get("lastsnd") is not None]
        return {
            "sockets_last": len(last),
            "rtt_ms": q([r["rtt"] for r in allrows if r.get("rtt")]),
            "minrtt_ms": q([r["minrtt"] for r in allrows if r.get("minrtt")]),
            "idle_s": q(idle) | {"hist": hist(idle, [0, 1, 5, 10, 30, 60, 120, 180, 300])},
            "rate_Bps": q(tot), "down_Bps": q(down), "up_Bps": q(up),
            "active_share": len(active) / max(1, len(tot)), "active_rate_Bps": q(active),
            "rate_hist": hist(tot, [0, 100, 1000, 10e3, 100e3, 1e6, 10e6]),
            "top1pct_share": top1, "top10pct_share": top10,
            "total_down_Bps_per_sample": sum(down) / max(1, len(rows_list) - 1), "total_up_Bps_per_sample": sum(up) / max(1, len(rows_list) - 1),
            "bytes_so_far": q([r["acked"] + r["recv"] for r in last]),
            "down_up_ratio": (sum(down) / sum(up)) if sum(up) else None,
            "seg_in_size": (sum(r["recv"] for r in last) / max(1, sum(r["dsegs_in"] for r in last))),
            "seg_out_size": (sum(r["acked"] for r in last) / max(1, sum(r["dsegs_out"] for r in last))),
            "segs_in_per_s": q([r["d_segs_in"] for r in withd]), "segs_out_per_s": q([r["d_segs_out"] for r in withd]),
            "retrans_per_s_total": sum(r["d_retrans"] for r in withd) / max(1, len(rows_list) - 1),
            "sendq": q([r["sendq"] for r in last]), "sendq_nonzero": sum(1 for r in last if r["sendq"] > 0),
            "recvq_nonzero": sum(1 for r in last if r["recvq"] > 0),
        }
    res["traffic"] = {side: summarize(deep[side], side) for side in ("in", "out") if len(deep[side]) >= 2}
    res["udp"] = udp
    res["proc_series"] = series["proc"]
    res["states_series"] = series["states"]

    # per core over the window
    pc = {}
    for n in C:
        cpu = [r[n]["cpu"] for r in series["proc"] if n in r]
        pc[n] = {"cpu_cores": q(cpu), "rss_mb": (series["proc"][-1].get(n, {}).get("VmRSS", 0) / 1024) if series["proc"] else None,
                 "threads": series["proc"][-1].get(n, {}).get("Threads") if series["proc"] else None,
                 "cpus": C[n].get("cpus")}
        a, b = res["metrics_start"].get(n, {}), res["metrics_end"].get(n, {})
        if a.get("NumGC") is not None and b.get("NumGC") is not None:
            pc[n]["gc_per_min"] = (b["NumGC"] - a["NumGC"]) / span * 60
            pc[n]["gc_pause_ms_per_s"] = (b["PauseTotalNs"] - a["PauseTotalNs"]) / 1e6 / span
            pc[n]["alloc_MBps"] = (b["TotalAlloc"] - a["TotalAlloc"]) / 1e6 / span
            pc[n]["mallocs_per_s"] = (b["Mallocs"] - a["Mallocs"]) / span
        pc[n]["goroutines"] = b.get("goroutines")
        pc[n]["heap_inuse_mb"] = (b.get("HeapInuse") or 0) / 1e6
        pc[n]["stack_inuse_mb"] = (b.get("StackInuse") or 0) / 1e6
    res["per_core"] = pc
    json.dump(res, open(os.path.join(OUTDIR, "observe.json"), "w"), indent=1, default=str)
    open(os.path.join(OUTDIR, "done"), "w").write("ok\n")


if __name__ == "__main__":
    main()
