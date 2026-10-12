#!/usr/bin/env python3
"""Turn bench results (results/MODE-CONNS.json) into a self-contained HTML
report: summary table, then charts of messages/s, CPU and p99 latency per
connection count for one core and for several.

  report.py RESULTS_DIR OUT.html [title]
"""
import html, json, os, re, sys

PHASES = ["idle", "light", "medium", "heavy"]
COLORS = {"single": "#d4483b", "multi": "#1f8a70"}
LABEL = {"single": "1 core × 16 CPUs", "multi": "8 cores × 2 CPUs"}


def load(d):
    out = {}
    for f in os.listdir(d):
        m = re.match(r"^(single|multi)-(\d+)\.json$", f)
        if m:
            out[(m.group(1), int(m.group(2)))] = json.load(open(os.path.join(d, f)))
    return out


def phase(r, name):
    return next((p for p in r["phases"] if p["name"] == name), None)


def fmt(v, d=1):
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:,.{d}f}"
    return f"{v:,}"


def chart(title, unit, series, xs, logy=False):
    """series: {mode: [(x, y)]} -> inline SVG line chart"""
    W, H, L, R, T, B = 460, 260, 64, 16, 34, 40
    ys = [y for pts in series.values() for _, y in pts if y is not None]
    if not ys:
        return ""
    ymax = max(ys) * 1.15 or 1
    def X(x):
        return L + (xs.index(x)) * (W - L - R) / max(1, len(xs) - 1)
    def Y(y):
        return T + (H - T - B) * (1 - y / ymax)
    parts = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="{html.escape(title)}">',
             f'<text x="{L}" y="20" class="ct">{html.escape(title)}</text>']
    for i in range(5):
        y = ymax * i / 4
        parts.append(f'<line x1="{L}" x2="{W-R}" y1="{Y(y):.1f}" y2="{Y(y):.1f}" class="grid"/>')
        parts.append(f'<text x="{L-6}" y="{Y(y)+4:.1f}" class="ax" text-anchor="end">{fmt(y, 0 if ymax > 20 else 1)}</text>')
    for x in xs:
        parts.append(f'<text x="{X(x):.1f}" y="{H-B+18}" class="ax" text-anchor="middle">{x//1000}k</text>')
    parts.append(f'<text x="{W-R}" y="{H-6}" class="ax" text-anchor="end">connections · {html.escape(unit)}</text>')
    for mode, pts in series.items():
        pts = [(x, y) for x, y in pts if y is not None]
        if not pts:
            continue
        d = " ".join(f"{'M' if i == 0 else 'L'}{X(x):.1f},{Y(y):.1f}" for i, (x, y) in enumerate(pts))
        parts.append(f'<path d="{d}" stroke="{COLORS[mode]}" class="ln"/>')
        for x, y in pts:
            parts.append(f'<circle cx="{X(x):.1f}" cy="{Y(y):.1f}" r="3.5" fill="{COLORS[mode]}"/>')
    parts.append("</svg>")
    return "".join(parts)


def main():
    d, out = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "One xray core vs several"
    res = load(d)
    xs = sorted({c for _, c in res})
    rows = []
    for c in xs:
        for ph in PHASES:
            for mode in ("single", "multi"):
                r = res.get((mode, c))
                if not r:
                    continue
                p = phase(r, ph)
                if not p:
                    continue
                s = p.get("server", {})
                cores = r.get("cores", 16) or 16
                rows.append(f"<tr class='{mode}'><td>{c//1000}k</td><td>{ph}</td><td><span class='dot' style='background:{COLORS[mode]}'></span>{LABEL[mode]}</td>"
                            f"<td>{fmt(r['established'])}</td><td>{fmt(p['offeredPerSec'],0)}</td><td>{fmt(p['recvPerSec'],0)}</td>"
                            f"<td>{fmt(p['rttMs']['p50'],2)}</td><td>{fmt(p['rttMs']['p99'],1)}</td><td>{fmt(p['rttMs']['p999'],1)}</td>"
                            f"<td>{fmt(p['timeouts']+p['errors'])}</td><td>{fmt(s.get('coreCPU'),2)}</td><td>{fmt(100*s.get('coreCPU',0)/cores,0)}%</td>"
                            f"<td>{fmt(s.get('rssGB'),1)}</td><td>{fmt(s.get('gcPauseMs'),0)}</td></tr>")
    charts = []
    for ph in ("light", "medium", "heavy"):
        def ser(key):
            return {m: [(c, key(phase(res[(m, c)], ph), res[(m, c)])) if (m, c) in res and phase(res[(m, c)], ph) else (c, None) for c in xs] for m in ("single", "multi")}
        charts.append(chart(f"{ph}: messages answered per second", "msg/s", ser(lambda p, r: p["recvPerSec"]), xs))
        charts.append(chart(f"{ph}: CPU cores used by xray", "cores", ser(lambda p, r: p["server"].get("coreCPU")), xs))
        charts.append(chart(f"{ph}: p99 round trip", "ms", ser(lambda p, r: p["rttMs"]["p99"]), xs))
        charts.append(chart(f"{ph}: CPU per 1000 msg/s", "cores", ser(lambda p, r: 1000 * p["server"].get("coreCPU", 0) / p["recvPerSec"] if p["recvPerSec"] else None), xs))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --text:#1c2230; --muted:#5d6678; --line:#e3e6ec; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#11151d; --card:#1a2030; --text:#e4e8f0; --muted:#9aa4b8; --line:#2b3346; }} }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
main {{ max-width:1180px; margin:0 auto; padding:24px 16px 48px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:28px 0 10px; }}
p.sub {{ color:var(--muted); margin:0 0 16px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }}
.tbl {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; white-space:nowrap; }}
th, td {{ padding:6px 8px; border-bottom:1px solid var(--line); text-align:right; }}
th:nth-child(-n+3), td:nth-child(-n+3) {{ text-align:left; }}
th {{ color:var(--muted); font-weight:600; }}
.dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }}
.grid2 {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:12px; }}
.chart {{ width:100%; height:auto; }} .ct {{ font-size:13px; font-weight:600; fill:var(--text); }}
.ax {{ font-size:11px; fill:var(--muted); }} .grid {{ stroke:var(--line); }} .ln {{ fill:none; stroke-width:2.5; }}
.legend span {{ margin-right:16px; }}
</style></head><body><main>
<h1>{html.escape(title)}</h1>
<p class="sub">VLESS over TCP with the HTTP header, 1,000 clients, 64-byte messages echoed back. Same 16 CPUs for both setups; load generator on other CPUs.
Phases: idle (connections held), light (each connection sends every 10 s), medium (every 5 s), heavy (every 2 s).</p>
<p class="legend"><span><span class="dot" style="background:{COLORS['single']}"></span>{LABEL['single']}</span><span><span class="dot" style="background:{COLORS['multi']}"></span>{LABEL['multi']}</span></p>
<div class="grid2">{''.join(f'<div class="card">{c}</div>' for c in charts if c)}</div>
<h2>All numbers</h2>
<div class="card tbl"><table><tr><th>conns</th><th>phase</th><th>setup</th><th>established</th><th>offered msg/s</th><th>answered msg/s</th><th>p50 ms</th><th>p99 ms</th><th>p99.9 ms</th><th>lost</th><th>cores used</th><th>of its 16</th><th>RAM GB</th><th>GC pause ms</th></tr>
{''.join(rows)}</table></div>
</main></body></html>"""
    open(out, "w").write(page)
    print("wrote", out)


if __name__ == "__main__":
    main()
