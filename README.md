# x-ui (dialect build)

A fork of [3x-ui](https://github.com/MHSanaei/3x-ui) v2.9.0 that adds **VLESS
dialects** — a per-inbound set of protocol version bytes, so an inbound only
answers clients whose core speaks one of them.

It ships its own Xray core and cannot use another one.

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

The core is [Xray-core v26.3.27](https://github.com/XTLS/Xray-core) plus the
dialect change and nothing else.

## Install

Nothing is interactive.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh)
```

Defaults: username `fardin`, password `fardin`, port `60000`, path `hetzner`,
SQLite, no SSL.

Seed the database from a URL at install time:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/F4RD1N/x-ui/main/install.sh) db=https://host/x-ui.db
```

Any default can be overridden the same way (`port=`, `user=`, `pass=`, `path=`)
or through the matching `XUI_*` environment variables.

The installer needs systemd (Debian, Ubuntu, RHEL-family, Arch). It unpacks and
checks the new release before it stops anything, and puts the previous panel
back if the new one does not start.

## Server tuning

Every install and update also tunes the server for x-ui (`x-ui tune`):

- the service gets `LimitNOFILE=1048576` (more on large machines),
  `TasksMax=infinity`, and a `GOMEMLIMIT` sized from the RAM;
- kernel limits are raised: local port range 10000-65535, accept and SYN
  queues, TIME_WAIT and orphan limits, socket buffers, conntrack (when it is
  loaded; up to 32M entries from 512 GiB of RAM), BBR with fq;
- the NICs under the default routes are tuned (see below);
- where the OS sets the CPU clock, the `performance` governor, and idle states
  that take more than 10 µs to wake from are turned off (again at every
  boot). A box whose BIOS or hypervisor sets the clock, and one where tuned,
  cpupower, the kernel command line or an admin decided, is left alone;
- on a fresh install (and with `x-ui tune apply`), but never on an update:
  a local DNS cache (unbound, many threads, forwarding to the resolvers the
  server used before) that `/etc/resolv.conf` names first, the old resolver
  second: systemd-resolved, on one thread, drops lookups on a busy server, and
  each drop is a 5 s wait for a user's connection. It is only switched to once
  it answers, and a server with a DNS server of its own, or whose
  `resolv.conf` NetworkManager or resolvconf writes, is left alone. The
  uplink's addresses are kept through a link drop (a systemd-networkd drop-in,
  like netplan's `ignore-carrier`), so the per-core outgoing IPs and their
  connections live through it. Also chrony when no time-sync client is installed (VMess and Shadowsocks 2022
  reject clients whose clock is off), and a 1 GiB swapfile on VMs with less
  than 1.75 GiB of RAM. A time-sync client that is turned off stays off, and
  a package you removed is not installed again. x-ui no longer installs
  irqbalance: when it is installed, x-ui only takes the uplink NICs'
  interrupts away from it (a policy script) and it keeps balancing the rest.
  If you set `IRQBALANCE_ARGS` yourself, add
  `--policyscript=/var/lib/x-ui/tune/irqbalance-policy` to it and run
  `x-ui tune apply`; until then the NICs' interrupts stay with irqbalance.

The NIC's interrupts are placed by the xray instances' CPU split: the queues
RSS spreads by hash go one per physical core, NIC-local cores first, shared
out so that no instance carries more than its share (free CPUs first), and
each CPU sends (XPS) on the queue whose interrupt is on its own core. Where
the queues do not divide evenly (some instances hold one more), the RSS table
is weighted so that each instance's share of the packets follows its CPUs, and
the free CPUs' queues keep an even share (on ixgbe, igb, igc, i40e, ice and
mlx5, which change it without a reset; a table someone else set is kept, and
revert makes x-ui's even again). The panel re-places the interrupts and
re-weighs the table whenever the split changes. Before going back to an x-ui
without weighted tables, make them even (`ethtool -X <nic> equal <queues>`,
the RSS queues): an older x-ui places the interrupts by the table's weights.
On ixgbe, igb and igc, UDP is hashed on ports as well as addresses (their
default is addresses only).
A single-queue NIC (a typical VPS) gets RPS and RFS instead. An uplink that
came up before fq was the default qdisc (at boot, before the sysctls) keeps
the kernel's default of then, pfifo_fast or fq_codel: it gets fq (mq with fq
on each queue) once, unless someone set up its root qdisc or chose another
default qdisc; revert puts the kernel's default back (fq took over the
pacing of the connections open then, so those that use BBR send unpaced
until they close; an x-ui restart closes xray's). The queue count
is only ever raised, to one queue per physical core near the NIC, and never
while the server is in use: at boot, before x-ui starts
(`x-ui-nic.service`), or with `x-ui tune queues --now` (the link resets for a
few seconds; if the gateway stops answering, the old count is put back).
Interrupts placed by someone else are kept (`x-ui tune apply --take-irqs`
hands them over). Revert puts every value back, but leaves raised queues
until the next reboot.

It only ever raises a limit: a value set higher elsewhere (another
`/etc/sysctl.d` file, `/etc/sysctl.conf`, a drop-in of your own) is kept, and
so is a choice like `tcp_congestion_control` made in a file of your own. It
writes only its own files (`/etc/sysctl.d/51-x-ui.conf`,
`/etc/systemd/system/x-ui.service.d/20-x-ui-tuning.conf`, and a few more listed
by `x-ui tune -h`) and re-applies the kernel settings each time x-ui starts.
Sysctl files whose names sort after `51-x-ui.conf` win at boot; after changing
any sysctl file, run `x-ui tune apply` so x-ui's file follows it.

```bash
x-ui tune status    # what is set, what is kept, and health counters
x-ui tune apply     # apply now
x-ui tune queues    # the NICs' queue counts (--now raises them now)
x-ui tune revert    # undo exactly, and keep it off for later updates
```

`bash install.sh tune=off` skips it for one install.

## Anti-abuse

`x-ui anti-abuse` keeps the server's IPs out of abuse reports. It is off until
you turn it on:

- outgoing connections to brute-force and spam ports are refused (TCP 22, 23,
  25, 135, 139, 445, 1433, 2323, 3389, 5900; UDP 137, 138, 161, 1900, 11211);
- private and reserved addresses are refused through the internet uplink (what
  a hoster reports as a netscan); the uplink's own subnets and routes still work;
- port and net scans are refused: more than 50 new hosts per second on a port
  from one outgoing IP, or 30 new ports per second on one host. Web ports
  (TCP 80/443, UDP 443), loopback and destinations already in use are never
  limited;
- a host that does not answer this server at all (100 or more connection
  attempts waiting, not one working connection; checked every minute) is
  refused for 10 minutes: apps fail at once and try another address instead
  of waiting out a timeout, and a flood at that target stops. A busy host
  always has working connections, so it is never refused;
- fail2ban bans an IP after 2 failed SSH logins in 10 minutes, for an hour and
  longer each time it comes back. The address you run it from is never banned.

It is an nftables table of its own (`x-ui-anti-abuse.service`), without
conntrack, so it costs nothing on a busy server and leaves other firewalls
alone.

```bash
x-ui anti-abuse          # turn it on (again after network changes)
x-ui anti-abuse status   # what it has refused, and SSH bans
x-ui anti-abuse off      # remove it all
```

## Updating

The **x-ui** card on the overview page has an **Update** button. It checks this
repository for a newer release, tells you whether one exists, and on
confirmation replaces the panel and restarts it. Your database, inbounds and
login are kept — an update deliberately does not re-apply the install defaults.

The panel and its core are always replaced together, because a release carries
the two built against each other. There is still no way to update the core on
its own.

From the shell it is the same thing (it also keeps the login):

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

## Xray instances

A single xray process carrying hundreds of thousands of TCP connections runs out
of steam long before the machine does. So every inbound runs in a named **Xray
instance**, and every instance is its own xray process:

- **Xray instance** (inbound form): `xray-1`, `xray-2`, … by default, one per
  inbound. Give several inbounds the same name to put them in one process.
- **CPU cores** (inbound form): `Auto` by default, or a fixed number. The
  number counts logical CPUs (threads). Fixed instances get that many CPUs of
  their own, on one NUMA node when one has room, whole cores first; the auto
  instances split the rest evenly (one CPU apart at most), each on one NUMA node
  when that keeps the split even. On 28 CPUs, two auto instances get 14 each;
  with one fixed at 10, the auto one gets 18. On servers with 2 threads per
  core, an even number keeps whole cores, and two instances share a core only
  when the node has too few for each to have its own (NUMA off on two
  sockets: each socket counts as a node). The form shows the server's total
  cores and how many this instance can have, and more than that is refused. The
  value belongs to the instance, so it applies to all of its inbounds.

Each process runs the template (routing, outbounds, DNS, …) plus its own
inbounds and its own API port, and is pinned to its cores. The overview page
shows the CPU split in a card of its own, then a card per instance with its
state, cores and CPUs, CPU use, TCP connections, memory, threads and uptime. Each
instance can be stopped, started and restarted on its own: a stopped instance
stays stopped through inbound edits and crash checks, and its CPUs go to the auto
instances, until you start it again, restart Xray as a whole or restart the panel.

Changes still apply without restarting anything that does not need it: adding,
editing or removing an inbound or client goes through the API of the process
that runs it, a new instance only starts its own process, an emptied one stops,
and a change of cores moves running processes to their new CPUs in place.

On upgrade, each existing inbound gets its own instance. An imported inbound
also gets a new one.

**Outgoing IP** (the pencil on an instance's card) makes the instance's
freedom outbounds send from one of the server's own addresses (`sendThrough`).
Every UDP flow a user opens (DNS, QUIC, calls) holds a local port of its own,
and all instances sending from the default address share its ~64k ports: near
full, every new flow's port search spins in the kernel, the CPU goes to 100% and
traffic collapses, however big the server. With an address each, an instance's
UDP flows have that address's whole port range, and its TCP connections still
share ports by destination (`IP_BIND_ADDRESS_NO_PORT`). The system resolver's
lookups are the exception: each takes a port that must be free on every
address. An address is accepted only if it is an IPv4 address on the server and
reaches the internet; an instance with one reaches IPv4 destinations only, and
outbounds set to prefer IPv6 keep the default address. Setting it restarts that
instance only, and an instance whose address comes or goes later (late at boot,
say) is restarted onto it, or back onto the default, within 30 seconds. The
card also shows the **UDP ports** in use where the instance takes them from,
orange from 80% and red from 90% of that or of the ports held on all addresses.
From the shell: `x-ui setting -xrayEgress "xray-1=IP,xray-2=IP"` (applied at
the next panel restart).

**Multi Instance** (the inbound's ⋮ menu) manages the inbound's
**sub-inbounds**: the same inbound on other ports, each in an xray instance of
its own. A sub-inbound has only four settings of its own — port, instance, CPU
cores, on/off — and shares everything else with its inbound: protocol,
settings, transport and every client. A client works on every port with one
traffic total and one IP limit, and a sub-inbound's traffic counts on its
inbound. **Add** puts new sub-inbounds on the ports after the last one in use
(cores per instance Auto or a number; **Max** adds as many as the free CPU cores
allow), every row can be edited, switched off or removed, and **Save** applies
the list: new instances start, removed or disabled ones stop, and the others
keep running. Adding or removing clients reaches every sub-inbound through the
API.

Tests: `go test ./...` (the instance tests start real cores when one is
installed or `XRAY_TEST_BINARY` points at one), and
`tests/instances/run-isolated.sh`, which runs a throwaway panel in a network
namespace and checks instances, CPU pinning under load, traffic counting, TCP
counts and, with `UI=1`, the pages in a browser.

## Diagnostics

`x-ui diag` shows the server as x-ui sees it and changes nothing:

- the CPUs: sockets, cores, threads per core, NUMA nodes with their CPUs and
  memory;
- each NIC under the default routes: driver, NUMA node, speed, queues, the RSS
  table and how UDP and TCP are hashed, which CPU each queue's interrupt runs
  on and which xray instance owns that CPU, irqbalance, XPS and RPS;
- a few seconds of live counters: busy, softirq and steal time per CPU,
  traffic, and dropped packets at the NIC and in the kernel;
- each xray instance: its CPUs and NUMA nodes, CPU use, threads, memory, open
  files, TCP connections, UDP ports against the pool, and the NIC interrupts
  on its CPUs against its fair share;
- TCP, conntrack and open-file counters against their limits;
- warnings, each with its fix where there is one.

```bash
x-ui diag               # the report, with a 3-second sample
x-ui diag --seconds 10  # a longer sample (0 to 30; 0: none)
x-ui diag --json        # the same as JSON
```

Install and update end with its short summary (`x-ui diag --summary`): what
was detected, and what x-ui set up.

## Other changes

- **Connection counts are cheap.** The overview's TCP and UDP totals come from
  `/proc/net/sockstat` instead of printing `/proc/net/tcp` every two seconds,
  which on a busy server cost seconds of CPU each time.
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
