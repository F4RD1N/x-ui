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

## Certificates by URL

Anywhere a certificate or key path is accepted — the panel's own certificate
settings and an inbound's TLS certificates — you may enter an
`http(s)://` link instead. On save the file is downloaded to `/etc/x-ui/certs`
and the field is replaced with the local path.

## Other changes

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
