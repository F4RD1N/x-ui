# x-ui (dialect build)

A fork of [3x-ui](https://github.com/MHSanaei/3x-ui) v2.9.0 that adds **VLESS
dialects** — a per-inbound set of protocol version bytes, so an inbound only
answers clients whose core speaks one of them.

It ships its own Xray core and cannot use another one.

Dialect11 adds native Go Orbit, DNS tunneling (DNSTT), OpenVPN, AnyTLS,
ShadowTLS, and Mieru inbounds/outbounds, optional client authentication modes,
and portable backup restoration. See [the implementation and configuration
guide](DIALECT11.md) for schemas, export requirements, and compatibility limits.
The [release verification report](DIALECT11-VERIFICATION.md) records completed
tests and the inherited SS2022 UDP dependency race that remains.
Version `2.9.0-dialect.11.1` fixes full-page rendering, native client filters,
outbound Save and GUI share links; see the [hotfix report](DIALECT11-HOTFIX.md).

## Dialects

A VLESS request begins with a version byte. Stock VLESS always sends `0`, and a
stock server accepts only `0`. This build makes that byte configurable per
inbound:

```
dialects: 4,5
```

means the inbound serves clients speaking dialect 4 or 5, and turns away
everyone else — including every stock client — before their user id is read. An
inbound that names no dialect behaves exactly as it always did.

Because the check is the first byte on the wire, a config extracted from a
client is useless against the server unless the core it is fed to speaks the
same dialect.

Share links and JSON subscriptions carry `x-dialect=<n>` / `"dialect": <n>` so a
client built from them speaks a dialect the inbound serves.

Listing more than one dialect is what makes a migration possible: set `0,4`
while old and new clients are both in the field, then drop to `4` once every
client has been updated.

### One core, fixed

The panel builds inbound protobufs in its own process when it applies a change
to the running core, so it has to parse configs with the same core it ships.
`go.mod` therefore points `github.com/xtls/xray-core` at `./core`, the fork in
this repository, and the panel's ability to download or switch the Xray core has
been removed. A stock core would silently drop `dialects` and quietly go back to
accepting stock VLESS only.

The core is based on [Xray-core v26.3.27](https://github.com/XTLS/Xray-core),
with the existing dialect features and the native protocol/authentication
extensions described in [DIALECT11.md](DIALECT11.md).

## Install

Nothing is interactive.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh)
```

Defaults: username `fardin`, password `fardin`, port `60000`, path `hetzner`,
SQLite, no SSL.

Seed the database from a URL at install time:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh) db=https://host/x-ui.db
```

Any default can be overridden the same way (`port=`, `user=`, `pass=`, `path=`)
or through the matching `XUI_*` environment variables.

Run on a server that already has the panel (and without `db=`, `user=`, `pass=`,
`port=` or `path=`), the same command updates it and keeps its login, port and
path.

### What every install and update sets up

| | |
|---|---|
| `x-ui protect` | The core's direct connections never reach this server's loopback (the core's API, its metrics, the DNS cache), its SSH and panel ports, or private networks; speed-test servers (iperf3) stay stopped. |
| `x-ui anti-abuse` | Outgoing connections to brute-force and spam ports (SSH, Telnet, SMTP and mail submission 465/587/2525, RDP, SMB, VNC, ...), to private networks through the uplink, and port/net scans are refused; a host that never answers is refused for 10 minutes (the dead-host check, every minute); brute force on other logins is cut short: a server's FTP, database (MySQL, PostgreSQL, Redis, MongoDB, ...), SIP, WinRM, MikroTik or Webmin port that gets more than 30 new connections a minute from this server is refused for an hour (longer while they keep coming), and POP3/IMAP connections over 60 a minute to one server are refused; fail2ban bans an IP after 2 failed SSH logins. New connections to networks that serve only abuse are refused too: Spamhaus DROP (hijacked and criminal networks, botnet command servers among them), fetched again every 6 hours, the last copy kept for boot and for when a source is down, and the sinkholes where researchers count infected devices: every network of The Shadowserver Foundation, plus Microsoft, BitSight, CERT.PL, Dr.Web, Kaspersky and others. They are refused whatever the routing template says, and every update applies them. Malware on a user's device that calls home there would otherwise get the server's IP onto Spamhaus XBL. With the DNS cache (and about 2 GB of memory), the cache also refuses about 190,000 names that serve only malware, phishing and botnets (HaGeZi's Threat Intelligence Feeds, mini; fetched with the lists), so the core cannot connect to a name on that list; names listed one per line in `/etc/x-ui/anti-abuse-allow-domains` are never refused. `x-ui anti-abuse status` shows what it refused and whether Spamhaus lists the server's IP (the 6-hourly run logs a listing: `journalctl -t x-ui-anti-abuse`). |
| `x-ui dns` | A local DNS cache (unbound at 127.0.0.1). It forwards to the fastest resolvers the server reaches, timed at setup -- often its provider's own, a fraction of a millisecond away. `/etc/resolv.conf` keeps two of them after 127.0.0.1 in case the cache does not answer. Left alone where something else manages DNS. |
| BBR | BBR with fq, unless another congestion control was chosen on the server. |
| Swap | On a fresh install of a machine with 2 GiB of RAM or less and no swap: a 1 GiB `/swapfile`. |
| Ports | The kernel's range for outgoing connections is 10000-65535 (the default 32768-60999 runs out on a busy server: the core's connections, or the outbound test, then fail with "address already in use"), with `tcp_tw_reuse` on; ports something already listens on inside the new range are reserved first. The panel keeps every port it and the core listen on out of that range (`ip_local_reserved_ports`), so a restart never finds one taken. A range or `tcp_tw_reuse` set in another sysctl file is kept. |
| Connection tracking | Where a firewall has the kernel's connection tracking loaded (nftables, iptables, ufw, fail2ban, Docker), its table is raised to 65536 slots per GiB of RAM (524288 on an 8 GB server, at most 4194304; never lowered), with a hash a quarter of that, and idle TCP connections are forgotten after an hour instead of the kernel's 5 days. A full table makes the kernel silently drop every new connection. Values set in another sysctl file are kept (and applied). Nothing is loaded where it is not in use; a udev rule applies the values whenever a firewall or Docker loads the module, also after every boot. |
| Network cards | The receive ring of every physical network card is raised to 4096 (or the card's maximum): at the usual 512 a busy server drops packets before the kernel sees them. Changing it resets the card for a second or two, so cards go one at a time and a bond keeps running on its other links; a server with a single card has that blip once. Applied again at every boot (`x-ui-host.service`). |
| CPU | Every core runs the `performance` cpufreq governor where the server can choose one (most virtual machines cannot), also at every boot. |
| Memory limit | The Go memory limit (`GOMEMLIMIT`) of the panel and the core comes from the memory the server has, worked out again at every start (so at every boot) and saved nowhere: 3/4 of what is left after the kernel's TCP buffers and a reserve for the system -- about 440 MiB on a 1 GB server, 15 GiB on a 24 GB one. A server made from a snapshot of a smaller one gets the limit for its own memory. A `GOMEMLIMIT` (or `GOGC=off`) in the service's environment is not used; to give x-ui less memory, set `MemoryMax=` in a drop-in (`systemctl edit x-ui`; updates rewrite `x-ui.service` itself) and the limit follows it. The panel's log shows the value. |

`x-ui protect off`, `x-ui anti-abuse off`, `x-ui dns off` and the menu's
**Disable BBR** undo them and are remembered: later updates leave them off until
they are turned on again. A congestion control, qdisc or fail2ban setting the
admin chose is kept, and a fail2ban the admin turned off stays off.
`anti-abuse=off` and `dns=off` skip those two for one run of the installer.
Uninstall removes all of it and puts `/etc/resolv.conf` back.

### Default routing

A fresh install's Xray template is an allow-list: SMTP, speed tests, IP-lookup
sites and tunnel/DDNS services are blocked first, then known apps, sites and
games are let through; anything else goes nowhere. An update keeps the template
the panel already runs (a panel that never saved one keeps the old built-in
default). The release build checks that the template loads with the geo files it
ships.

## Updating

The **x-ui** card on the overview page has an **Update** button. It checks this
repository for a newer release, tells you whether one exists, and on
confirmation replaces the panel and restarts it. Your database, inbounds and
login are kept — an update deliberately does not re-apply the install defaults.

The panel and its core are always replaced together, because a release carries
the two built against each other. There is still no way to update the core on
its own.

From the shell it is the same thing:

```bash
x-ui update
```

## Replacing the database later

```bash
x-ui db="https://host/x-ui.db"
```

The file is downloaded, checked for being a real SQLite database and passing an
integrity check, and only then swapped in; the previous database is kept until
the new one has opened successfully. The panel is restarted afterwards.

## Remote Xray config

**Xray Configs → Remote config** takes a URL and an interval in minutes. An
interval of `0` turns it off.

A fetched config is stored only if it survives three checks, so a bad file at
the far end of the URL cannot stop a running core:

1. it parses as JSON, and names at least one outbound — a config that parses to
   nothing (an error page that happens to be JSON) would otherwise start the
   core with no outbound and silently route nothing;
2. it is merged with the current inbounds and handed to the bundled core with
   `xray -test`, which is the same parse the core does at startup, so anything
   it would refuse to start on is refused here instead;
3. it actually differs from the config already in use, so an unchanged config
   never restarts the core.

If any check fails the reason is written to the panel log and the current
config is kept.

The section also shows **Last checked** and **Last applied**. Last checked is
written on every run, whatever the outcome; last applied only when a config was
actually stored. So a check time well ahead of an apply time is the normal,
healthy state — it means the config has not changed — and it is also how a URL
that has quietly stopped working shows up.

## Certificates by URL

Anywhere a certificate or key path is accepted — the panel's own certificate
settings and an inbound's TLS certificates — you may enter an
`http(s)://` link instead. On save the file is downloaded to `/etc/x-ui/certs`
and the field is replaced with the local path.

## Any path on WebSocket, HTTPUpgrade and TCP HTTP header

An inbound whose WebSocket or HTTPUpgrade path is `*` takes every path, so
each client can use a path of its own (`/feed/966695/assets/recent/media`,
`/a/b?ed=2560`, ...). Early data (`?ed=`) still works. Any other path must
still match exactly. Only the server needs this; clients are unchanged (a
client given `*` sends `/*`). The path then no longer hides the inbound:
anyone who opens a WebSocket on that port reaches VLESS, which still refuses
unknown users.

The same goes for a TCP inbound with the HTTP header (`"header": {"type":
"http"}`): a request path of `*` (or `/*`) in its list takes every path. The
query string after `?` is never compared, with or without `*`.

## Outgoing IP pools

Every UDP flow a direct (freedom) outbound opens takes one local port, and one
IP has only about 64k of them. A server with many users runs out, and the CPU
climbs while the kernel looks for free ports. Give the outbound several of the
server's IPs instead of one:

```json
{ "protocol": "freedom", "tag": "direct", "sendThrough": "203.0.113.11,203.0.113.12,203.0.113.13,203.0.113.14" }
```

Each IP adds its own ~64k ports. A user always leaves through the same IP of
the pool (picked from their address), so sites don't see their IP change.
Only the IPs the server actually has are used; the rest are skipped with a
warning in the log. Use IPs of one family (all IPv4 or all IPv6). The panel's
"Send Through" field takes the same list.

A TCP connection sent from a chosen IP (a pool or a single Send Through
address) leaves the choice of its local port to the kernel's `connect()`
(`IP_BIND_ADDRESS_NO_PORT`), so connections to different destinations share
ports. Before 11.15 each one took a port of that IP of its own, and a busy
server with few IPs spent most of its CPU in the kernel looking for a free
one.

## A bigger connection-tracking table (11.23)

A server whose firewall loads the kernel's connection tracking keeps one slot
for every connection through it, in a table of about 262144 slots by default,
and remembers an idle TCP connection for 5 days. On a busy VPN server the table
fills up with connections that ended long ago (the core closes idle ones after
5 minutes), and once it is full the kernel silently drops every new
connection: users see timeouts while the server looks healthy.

Every install and update now raises the table to 65536 slots per GiB of RAM
(524288 on an 8 GB server, at most 4194304; a larger table stays) with a hash
of a quarter of that, and forgets idle TCP connections after an hour. A slot
in use takes about 300 bytes, so 524288 full slots are about 150 MB. It is
applied live, with no restart. The module is usually loaded by the firewall or
Docker only after the boot's sysctl files were read, so on its own nothing
would take effect at boot -- neither x-ui's values nor ones an admin put in a
sysctl file. x-ui writes its values to `/etc/sysctl.d/60-x-ui.conf` with a `-`
(no complaint while the module is not there yet) and adds
`/etc/udev/rules.d/90-x-ui-conntrack.rules`, which applies the `net/netfilter`
values of every sysctl file the moment the module loads, whoever loads it (the
way `sysctl.d(5)` does it for `br_netfilter`). The setup prints what it did:

```
Connection tracking: table 262144 -> 524288, hash 65536 -> 131072, idle TCP kept 432000 s -> 3600 s
```

A server without connection tracking loaded is not changed now (`not in use
here`); the values wait in the file for a firewall to load it. Values set in
another sysctl file (also the old name `net.nf_conntrack_max`) are the admin's:
x-ui applies them and leaves them as they are. Uninstall removes the file and
the rule; the kernel keeps the values until the next reboot.

## Which CDN each sampled user came through (11.22)

`/debug/clientips` now also says which peer delivered each sampled IP: the
socket's own remote address, which behind a CDN is the CDN's edge server.
The answer gains a `peers` list of the same length and order as `ips`:

```
curl -s http://127.0.0.1:11111/debug/clientips
{"v":1,"recorded":183204,"ips":["151.232.10.5","2a01:5ec0:1000::1",...],"peers":["151.101.2.3","2a06:98c0:3600::103",...]}
```

`peers[i]` is the address that `ips[i]` arrived from, or `""` when it is
unknown (an inbound on a Unix socket, say). Matching it against Fastly's and
Cloudflare's ranges tells the users of each CDN apart. With the PROXY
protocol on an inbound (`acceptProxyProtocol`), the peer is the address the
PROXY header gives, as the core sees it everywhere else. `v`, `recorded` and
`ips` are exactly as in 11.21, so readers written for 11.21 keep working.

Recording stays as light: one 32-byte store under the same lock, about 10 ns
and no allocation (about 42 ns with 8 cores recording nonstop), and the ring
stays at 4096 entries. The full page is about twice as long as before and
takes about 0.26 ms to serve.

## Real client IPs of CDN users (11.21)

Behind a CDN (Cloudflare, Fastly, ...) the socket shows only the CDN's IP;
the user's own IP is in `X-Forwarded-For`, which the WebSocket, HTTPUpgrade
and XHTTP inbounds already use as the remote address. The core now keeps the
last 4096 of those forwarded IPs (IPv4 and IPv6), one per new connection
(an XHTTP connection counts once, not once per upload request), and the
metrics listener (`127.0.0.1:11111` in the default template) shows them:

```
curl -s http://127.0.0.1:11111/debug/clientips
{"v":1,"recorded":183204,"ips":["151.232.10.5","2a01:5ec0:1000::1",...]}
```

`ips` runs oldest to newest; `recorded` counts every IP recorded since the
core started. A few thousand recent IPs are enough to tell each operator's
share of the CDN users to within about 1.5 %, as long as the clients do
not forge the header. Connections that come without the header record
nothing.

The sample trusts `X-Forwarded-For` the same way the remote address does:
it takes the leftmost entry, and it records it when the connection arrives,
before the user's UUID is checked. Cloudflare and Fastly add their entry
after one the client already sent, so anyone who knows an inbound's host and
path (they are in every config) can fill the sample with IPs of their
choosing, through the CDN or straight to the server. That only skews the
numbers; it changes no traffic or routing. Treat a sudden run of one IP, or
of one network, as a sign of it.

It is light: recording is one 16-byte store under a lock, about 10 ns and no
allocation, and the old entries are simply overwritten. 30,000 new WebSocket
connections cost the core the same CPU with and without it (in the test,
about 0.7 ms of CPU per connection either way). Reading the page does not
touch the traffic counters, and `/debug/vars` is unchanged. Without a
metrics listener nothing new listens.

**The metrics listener now also shows recent client IPs, so keep it on
localhost** (`127.0.0.1`), as the default template does. Localhost is safe
only while `x-ui protect` is on (every install and update turns it on). The
core's direct outbound can reach `localhost`, or any name that points at
`127.0.0.1`, for the server's own VPN users, and only the direct guard stops
that. A Docker install never has the guard, and `x-ui protect off` takes it
away. There, any user connected to the server can read this list of other
users' IPs, as they can already read `/debug/vars`. Turn `x-ui protect` back
on, and in Docker leave the metrics listener out of the template.

## Set the login, port and path in one command (11.20)

```
x-ui update-info <username> <password> <port> <path>
x-ui update-info fardin fardin 60000 hetzner
```

Sets the panel's username, password, port and web base path without any
questions, restarts the panel, and prints the new access URL. Nothing is
changed unless everything is valid:

- the username has no spaces;
- the password is 1 to 72 characters;
- the port is a number from 1 to 65535 that no other program listens on;
- the path uses only letters, digits, `.` `_` `~` `-` and `/` between parts,
  with no `.` or `..` parts. `hetzner`, `/hetzner` and `/hetzner/` are the
  same, and `/` means no path.

Two-factor authentication is left as it is. Like any command line, the password
stays in the shell's history.

## Route every UDP destination (11.19)

Xray routes a UDP session once, by its first packet. Full-cone UDP (mux.cool
and XUDP, socks and shadowsocks UDP, ...) lets every later packet of the
session name its own destination, and a direct (freedom) outbound sent each one
there without routing it. With an allow-list routing (`blocked` first, only
listed domains, IPs and ports to `direct`) a session that opened to an allowed
destination, say `8.8.8.8:53`, could then reach any IP and port. Turn the check
on in the freedom outbound (off by default: the core then behaves as upstream):

```json
{ "protocol": "freedom", "tag": "direct", "settings": { "udpRouteEachDestination": true } }
```

The panel's outbound form has the same switch ("Route each UDP").

- **What passes.** The session's own destinations (the one it was routed by,
  the address it asked for before a sniffed domain replaced it, and the
  address the socket was dialed to) always pass, so a QUIC session allowed by
  its sniffed domain keeps working. Any other destination is routed by the
  core's router with the session's own inbound, user, source and sniffed
  protocol, as UDP to the new IP (or domain) and port, without DNS. The packet
  passes only if that route is this outbound's own tag. `blocked`, another
  outbound, a balancer that picks another outbound, or **no matching rule at
  all** drop it. A destination that only the routing's default (first)
  outbound would take is dropped even when that default is this outbound: list
  it in a rule. The session goes on; only the packet is dropped.
- **Overrides.** With `destinationOverride` set to an address every packet goes
  there anyway, and nothing is checked. With a port-only override packets are
  checked by the destination the client asked for, before the port changes.
- **Only freedom checks.** UDP that the routing sends to a proxy outbound (a
  vless/vmess/trojan/... outbound) is forwarded with each packet's own
  destination as before, and the upstream server decides where it goes. If
  that matters, turn the setting on in the upstream server's freedom outbound
  with an allow-list there.
- **Cost and bounds.** The router runs once per new destination of a session,
  and the decision is kept (allowed and denied); the packets after it cost one
  map lookup. A session routes at most 128 new destinations at once and 64 a
  second after that; a packet to a new destination over that is dropped without
  being routed (and counted), and tried again when the budget refills. A
  session keeps at most 1024 decisions (then forgets them and starts again),
  and all sessions of one outbound at most 262144.
- **Counters.** `outbound>>>{tag}>>>udp>>>dropped_packets` and
  `outbound>>>{tag}>>>udp>>>dropped_destinations` (read them with
  `xray api statsquery`). The panel's traffic job resets every stats counter
  every 10 seconds, so they show the last few seconds only.
- **Log.** At most one Info line a minute per outbound: how many packets and
  new destinations were dropped and an example, such as
  `freedom [direct]: udpRouteEachDestination dropped 3 UDP packets; 1 new destinations not routed to this outbound, e.g. 45.33.1.1:554 -> (no route)`.
  Nothing is logged per packet.
- **Older cores** (before 11.19) accept the key and ignore it: the hole stays
  open there.

## Other changes

- **The TCP/UDP connection counts are read from the kernel's totals**
  (`/proc/net/sockstat`), not by counting the lines of `/proc/net/tcp` and
  `/proc/net/udp`. With a few hundred thousand connections those files are
  hundreds of megabytes, take seconds to generate and hold the kernel's
  socket-table locks meanwhile; the panel read them every 2 seconds, which
  kept several cores busy and slowed the core's own socket work.

- **Network speed and traffic count the uplink only.** The overview's
  upload/download speed and total traffic come from the interfaces that carry
  the default route (for example `bond0`), not from every interface added up,
  which counted each packet twice on a bonded server (the bond and its member
  card) and again on a GRE tunnel. Without a default route every interface
  but the loopback is counted, as before.

- **Restarting Xray no longer races itself.** Stopping the core now waits for it
  to exit (escalating to `SIGKILL`) before the new one starts, which is what
  caused `address already in use` on a port the previous core still held. The
  core also runs in its own process group with `PDEATHSIG`, so a panel that is
  killed outright cannot leave an orphan holding the ports.

## Building

```bash
./build.sh                  # amd64 + arm64 into dist/
ARCHES=amd64 ./build.sh     # one architecture
```

The panel needs cgo (its SQLite driver is a cgo binding); cross-building the
other architecture needs the matching cross-compiler installed.
