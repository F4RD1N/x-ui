# Simulating the live server's users

`bench/` loaded the cores with a synthetic echo pattern. This directory
simulates what the users of a live server actually do, so one xray core can
be compared with several under a load that behaves like the real one.

- `observe.py` watches a live server (read-only, aggregates only, no
  addresses kept) and writes `observe.json` plus a CPU and heap profile of
  its busiest core.
- `../xsim` is the simulator: `xsim fit` runs the model in virtual time and
  prints it next to `observe.json`; `xsim users` and `xsim sites` run it for
  real.
- `model.json` is the model, fitted to 76.164.201.34 on 2026-10-13.
- `run.py` runs one setup (one core, or several) against a throwaway copy
  of the panel in namespaces of its own; `report.py` compares the runs.

## What the live server showed (2026-10-13 00:56 UTC, 5 minutes)

One inbound (VLESS, TCP with the HTTP header, dialect 4, a single client id
shared by everyone, sniffing off) and 9 sub-inbounds, 10 cores × 5 CPUs.

| | |
|---|---|
| client connections | 21.7k → 30k (mean 24.6k) from ~3,750 addresses (6,150 seen in 5 min) |
| new client connections | ~140/s |
| outgoing connections | 49k → 62k (mean 53k), opened at ~1,060/s, ~2% to dead addresses |
| UDP sockets (users' UDP) | ~6.4k |
| traffic | 207 MB/s to users, 11 MB/s from them |
| client round trip | min-RTT median 102 ms (p90 127, p99 218); smoothed p99 3.4 s |
| xray | 0.8–1.0 CPU per core (≈9 in all), ~900 MB and ~38k goroutines each |

The users' clients use **Xray mux** (Mux.Cool): almost every client
connection is a mux connection carrying ~2.4 sessions, which is why outgoing
connections open 7× as often as client ones. Their lifetimes cluster at
**~120 s**: the server's mux worker checks every 60 s and closes a
connection after two checks with nothing on it, and the clients do not
close idle mux connections themselves. A second cluster at **~15 s** is the
server's handshake timeout on connections that never send their request.
Outgoing sessions are mostly short (median 10 s) with a mass at 60–77 s
(sites' keep-alive timeouts). Half of xray's CPU is read/write syscalls,
a fifth the Go scheduler, a fifth the mux write path.

## The model (`model.json`)

A **device** is online for a while (lognormal, median 5 min, long tail),
alternates spells of use and pauses, and has a download/upload bandwidth and
a network class (round trip 85–300 ms, loss 0.3–3%). 70% of departures are
the device dropping off the network: the server keeps its connections until
they go idle and its mux rule closes them.

Each device has an Xray mux client: concurrency 8, XUDP concurrency 16, a
connection retired after 128 sessions, sessions placed by Xray's own picker
(the first connection that is not full, moved to the end of the list). 5% of
devices close idle mux connections themselves (16 s checks); the rest leave
them to the server.

Sessions, by class:

| class | what | how often |
|---|---|---|
| fresh-check | a new mux connection of its own with one small request, then left open | every 35–75 s |
| push | 5228/5222, heartbeats every 4–5 min, occasional pushes | 1 per device, kept |
| long-lived | messengers, SSH and the like; heartbeats, pushes | 4 per device, kept |
| api | 1–4 small requests, then closed after a few seconds; 3% to dead addresses | bursts of 1–14 while in use |
| keep-alive | a few requests, then idle until the site's keep-alive timeout (30–300 s) | while in use |
| media | up to 20 big responses (median 340 KB) | rare |
| upload | big requests (median 150 KB) | rare |
| udp | XUDP flows: 1 pkt/s median, 300 B, 1–4 replies each | while in use |

Plus connections that stall before their request (~0.004/s per device).

`xsim fit` against the live numbers (scale 1):

| | model | live |
|---|---|---|
| devices | 3,743 | 3,747 addresses |
| mux connections | 28.7k | 24.6k (21.7k–30k) |
| new mux connections/s | 119 | ~140 |
| TCP sessions | 56.4k | 53.2k |
| dials/s (dead) | 1,182 (19) | 1,061 (22) |
| UDP sessions | 6.3k | 6.4k |
| down / up MB/s | 218 / 12 | 207 / 11 |
| session lifetime p10/25/50/75/90 s | 2/4/10/50/74 | 2/2/10/60/78 |

## Running it

Build `xsim` (`go build -o sim/xsim ./tests/instances/xsim`), copy this
directory to the server, then as root:

    python3 run.py single --phases 1:600,2:600,4:600,8:600 --xray-cpus 0-27 --users-cpus 28-41 --sites-cpus 42-55
    python3 run.py multi --instances 10 --phases 1:600,2:600,4:600,8:600 --xray-cpus 0-27 --users-cpus 28-41 --sites-cpus 42-55
    python3 report.py results results/report.html /path/to/observe.json

A phase is `scale:seconds`; scale 1 is the live load. New devices come
online over `--ramp` seconds and the first `--warm` seconds of a phase are
not measured. The namespaces (`xs-u`, `xs-c`, `xs-s`) are removed at the end
(`--keep` keeps them; `run.py teardown` removes them).

Everything runs in its own namespaces with its own addresses and routes, but
it shares the machine's CPUs and kernel with whatever else runs there. The
users and the sites cost CPU too (roughly as much again as xray), so give
them their own CPUs and expect the box to run out before xray does if they
share.
