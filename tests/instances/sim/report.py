#!/usr/bin/env python3
"""Turn simulation results (RESULTS/single.json, RESULTS/multi.json) into one
HTML page: per load step, what the users got and what the cores used, one
core against several, plus the scale-1 step next to the live server it was
modelled on.

  report.py RESULTS OUT.html [observe.json]
"""
import html, json, os, sys

COLORS = {"single": "#d4483b", "multi": "#1f8a70"}


def load(d):
    out = {}
    for mode in ("single", "multi"):
        p = os.path.join(d, mode + ".json")
        if os.path.exists(p):
            out[mode] = json.load(open(p))
    return out


def label(r):
    return "1 core" if r["mode"] == "single" else f"{r['instances']} cores"


def fmt(v, d=1):
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:,.{d}f}"
    return f"{v:,}"


def rows_of(r):
    out = []
    for p in r["phases"]:
        u, s = p["users"], p["server"]
        per, tot = u["perSec"], u["totals"]
        sess = max(1, tot.get("sessions", 0))
        out.append({
            "scale": u["scale"], "devices": u["devices"], "mux": u["mux"], "tcp": u["tcpSessions"], "udp": u["udpSessions"],
            "down": per.get("downBytes", 0) / 1e6, "up": per.get("upBytes", 0) / 1e6, "sessPerSec": per.get("sessions", 0),
            "coreCPU": s.get("coreCPU"), "busy": (s.get("groups", {}).get("xray", {}) or {}).get("busy"),
            "soft": (s.get("groups", {}).get("xray", {}) or {}).get("softirq"),
            "rss": s.get("coreRSSGB"), "goroutines": s.get("goroutines"),
            "gc": sum((c.get("gcPerMin") or 0) for c in s.get("cores", {}).values()),
            "connect50": u["tcpConnectMs"]["p50"], "connect99": u["tcpConnectMs"]["p99"],
            "ttfb50": u["ttfbMs"]["p50"], "ttfb99": u["ttfbMs"]["p99"], "exch99": u["exchangeMs"]["p99"],
            "failPct": 100 * tot.get("sessionsFailed", 0) / sess, "busyClosed": tot.get("muxServerClosedBusy", 0),
            "media": u.get("mediaRateMet"), "usersCPU": (s.get("extra", {}).get("users") or {}).get("cpu"),
            "sitesCPU": (s.get("extra", {}).get("sites") or {}).get("cpu"), "dials": (s.get("tcp") or {}).get("Tcp.ActiveOpens"),
        })
    return out


def chart(title, unit, series, logy=False):
    W, H, L, R, T, B = 460, 250, 60, 16, 34, 40
    xs = sorted({x for pts in series.values() for x, _ in pts})
    ys = [y for pts in series.values() for _, y in pts if y is not None]
    if not ys or not xs:
        return ""
    ymax = max(ys) * 1.15 or 1
    X = lambda x: L + xs.index(x) * (W - L - R) / max(1, len(xs) - 1)
    Y = lambda y: T + (H - T - B) * (1 - y / ymax)
    p = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="{html.escape(title)}">',
         f'<text x="{L}" y="20" class="ct">{html.escape(title)}</text>']
    for i in range(5):
        y = ymax * i / 4
        p.append(f'<line x1="{L}" x2="{W - R}" y1="{Y(y):.1f}" y2="{Y(y):.1f}" class="grid"/>')
        p.append(f'<text x="{L - 6}" y="{Y(y) + 4:.1f}" class="ax" text-anchor="end">{fmt(y, 0 if ymax > 20 else 1)}</text>')
    for x in xs:
        p.append(f'<text x="{X(x):.1f}" y="{H - B + 18}" class="ax" text-anchor="middle">{x:g}×</text>')
    p.append(f'<text x="{W - R}" y="{H - 6}" class="ax" text-anchor="end">load (× live) · {html.escape(unit)}</text>')
    for mode, pts in series.items():
        pts = [(x, y) for x, y in pts if y is not None]
        if not pts:
            continue
        d = " ".join(f"{'M' if i == 0 else 'L'}{X(x):.1f},{Y(y):.1f}" for i, (x, y) in enumerate(pts))
        p.append(f'<path d="{d}" stroke="{COLORS[mode]}" class="ln"/>')
        for x, y in pts:
            p.append(f'<circle cx="{X(x):.1f}" cy="{Y(y):.1f}" r="3.5" fill="{COLORS[mode]}"/>')
    p.append("</svg>")
    return "".join(p)


def main():
    d, out = sys.argv[1], sys.argv[2]
    obs = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
    res = load(d)
    if not res:
        raise SystemExit("no results in " + d)
    rows = {m: rows_of(r) for m, r in res.items()}
    labels = {m: label(r) for m, r in res.items()}
    charts = []
    for key, title, unit in [("coreCPU", "CPU used by xray", "cores"), ("busy", "Busy share of xray's CPUs", "%"),
                             ("ttfb99", "Time to first byte, p99", "ms"), ("ttfb50", "Time to first byte, median", "ms"),
                             ("connect99", "TCP connect to the inbound, p99", "ms"), ("failPct", "Sessions failed", "%"),
                             ("rss", "xray memory", "GB"), ("down", "Delivered to users", "MB/s")]:
        series = {m: [(r["scale"], (r[key] * 100 if key == "busy" and r[key] is not None else r[key])) for r in rs] for m, rs in rows.items()}
        charts.append(chart(title, unit, series))
    cols = [("scale", "load", 0), ("devices", "devices", 0), ("mux", "mux conns", 0), ("tcp", "TCP sessions", 0), ("udp", "UDP", 0),
            ("sessPerSec", "sessions/s", 0), ("down", "down MB/s", 1), ("coreCPU", "xray cores used", 2), ("busy", "CPUs busy", 0),
            ("rss", "RAM GB", 1), ("goroutines", "goroutines", 0), ("gc", "GC/min", 1), ("connect50", "connect p50 ms", 0),
            ("connect99", "connect p99", 0), ("ttfb50", "TTFB p50 ms", 0), ("ttfb99", "TTFB p99", 0), ("failPct", "failed %", 2),
            ("busyClosed", "busy mux closed", 0), ("media", "media speed", 2), ("usersCPU", "users CPU", 1), ("sitesCPU", "sites CPU", 1)]
    trs = []
    for m, rs in rows.items():
        for r in rs:
            tds = []
            for k, _, dd in cols:
                v = r[k]
                if k == "busy" and v is not None:
                    v = f"{v * 100:.0f}%"
                elif k == "scale":
                    v = f"{v:g}×"
                else:
                    v = fmt(float(v) if isinstance(v, (int, float)) else v, dd)
                tds.append(f"<td>{v}</td>")
            trs.append(f"<tr><td><span class='dot' style='background:{COLORS[m]}'></span>{html.escape(labels[m])}</td>{''.join(tds)}</tr>")
    calib = ""
    if obs:
        live = {"mux conns": obs["conns"]["in_now"]["mean"], "TCP sessions": obs["conns"]["out_now"]["mean"],
                "dials/s": obs["kernel_rates"].get("Tcp.ActiveOpens"), "down MB/s": obs["traffic"]["in"]["total_down_Bps_per_sample"] / 1e6,
                "xray cores used": sum(c["cpu_cores"]["mean"] for c in obs["per_core"].values())}
        trs2 = []
        for m, rs in rows.items():
            one = next((r for r in rs if abs(r["scale"] - 1) < 1e-9), None)
            if one:
                sim = {"mux conns": one["mux"], "TCP sessions": one["tcp"], "dials/s": one["dials"], "down MB/s": one["down"], "xray cores used": one["coreCPU"]}
                trs2.append("<tr><td>" + html.escape(labels[m]) + " (simulated, 1×)</td>" + "".join(f"<td>{fmt(sim[k], 1)}</td>" for k in live) + "</tr>")
        if trs2:
            calib = ("<h2>The simulation at 1× next to the live server</h2><div class='card tbl'><table><tr><th></th>" +
                     "".join(f"<th>{html.escape(k)}</th>" for k in live) + "</tr><tr><td>live (10 cores × 5 CPUs)</td>" +
                     "".join(f"<td>{fmt(v, 1)}</td>" for v in live.values()) + "</tr>" + "".join(trs2) + "</table></div>")
    first = next(iter(res.values()))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>User simulation</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --text:#1c2230; --muted:#5d6678; --line:#e3e6ec; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#11151d; --card:#1a2030; --text:#e4e8f0; --muted:#9aa4b8; --line:#2b3346; }} }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
main {{ max-width:1240px; margin:0 auto; padding:24px 16px 48px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:28px 0 10px; }}
p.sub {{ color:var(--muted); margin:0 0 16px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }}
.tbl {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; white-space:nowrap; }}
th, td {{ padding:6px 8px; border-bottom:1px solid var(--line); text-align:right; }}
th:first-child, td:first-child {{ text-align:left; }}
th {{ color:var(--muted); font-weight:600; }}
.dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }}
.grid2 {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:12px; }}
.chart {{ width:100%; height:auto; }} .ct {{ font-size:13px; font-weight:600; fill:var(--text); }}
.ax {{ font-size:11px; fill:var(--muted); }} .grid {{ stroke:var(--line); }} .ln {{ fill:none; stroke-width:2.5; }}
.legend span {{ margin-right:16px; }}
</style></head><body><main>
<h1>Simulated users: one xray core against several</h1>
<p class="sub">Devices modelled on the live server's users (Xray mux clients, VLESS over TCP with the HTTP header, dialect 4), at multiples of its load.
xray on CPUs {html.escape(first['xrayCPUs'])}; users on {html.escape(first['usersCPUs'])}; sites on {html.escape(first['sitesCPUs'])}.</p>
<p class="legend">{''.join(f"<span><span class='dot' style='background:{COLORS[m]}'></span>{html.escape(labels[m])}</span>" for m in res)}</p>
<div class="grid2">{''.join(f'<div class="card">{c}</div>' for c in charts if c)}</div>
{calib}
<h2>All numbers</h2>
<div class="card tbl"><table><tr><th>setup</th>{''.join(f'<th>{html.escape(t)}</th>' for _, t, _ in cols)}</tr>{''.join(trs)}</table></div>
</main></body></html>"""
    open(out, "w").write(page)
    print("wrote", out)


if __name__ == "__main__":
    main()
