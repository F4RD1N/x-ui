# Dialect11.5 release verification

Verified on 2026-11-03. This patch leaves deployment fields for the operator,
preserves automatic cryptography, and repairs the panel updater lifecycle.
Implementation and configuration behavior are described in
[DIALECT11-DEFAULTS.md](DIALECT11-DEFAULTS.md).

## Results

| Check | Result |
| --- | --- |
| Complete panel Go module, race detector | 604 named test/subtest passes across 9 tested packages; zero failures |
| Updater lifecycle, race detector | 9 groups passed, including real systemd with local fake downloads/installers |
| Updater browser/controller | 27 asynchronous UI cases and 5 existing restore cases passed; authenticated controller tests passed under the race detector |
| Independent native browser review | 53 scenarios passed; all six protocols, explicit prerequisites, edit/import/clone/restore, stale requests, manual edits and normalized identities |
| Native model/helper checks | 132 checks passed, including new explicit-deployment and metadata/mode coverage |
| Candidate AMD64 protocol traffic | 149 checks passed using the unchanged custom 25.3.6 client; final packaged AMD64 core is byte-identical to this tested core |
| Final packaged AMD64 persistence | 63 exact browser-request save/export/restart checks passed across all six protocols; no request-body repairs |
| Additional normalized identity persistence | 12 exact-request checks passed; four exported identities separately matched certificate SAN and retained CA trust |
| Final packaged ARM64 runtime under QEMU | 191 checks passed; zero failures; approximately 59 seconds |
| OpenVPN empty-DNS regression | Omitted/null legacy DNS, explicitly empty DNS, and supplied IPv4/IPv6 resolvers retained their intended behavior through repeated parse/serialize cycles under the race detector |
| Shell/build checks | Installer/build syntax and whitespace checks passed; both release architectures built; default Xray template parsed against bundled geodata |

The ARM matrix ran the actual packaged ARM panel and core. It checked ELF and
archive-member identities, release version, served JavaScript/cache keys, all
six protocols with two users, incorrect credential rejection, HTTP transfers
over 1 MiB, UDP payloads, server outbound reuse, backup restoration, and a third
OpenVPN client issued after restore. All 13 raw client exports parsed using the
actual ARM core. SQLite integrity and explicit OpenVPN DNS preservation passed.
ARM results reflect emulation, not physical ARM hardware performance.

The panel-wide Go run skipped four opt-in cases. The real-systemd case passed
in its separate opted-in run; the two browser-export fixture cases passed with
their captured fixtures. The unchanged real-geodata normalization case was not
repeated for this patch; the release build did validate the complete default
server template against its bundled geodata.

## Defects caught by verification

- An ungenerated AnyTLS form could pass the initial Save guard. Identity and
  certificate checks now prevent that.
- Entering an identity before generation could lose generated CA trust when
  metadata was merged. The merge now preserves both explicit identity and trust.
- Whitespace or bracketed IPv6 input could disagree with the generated
  certificate identity. Explicit values now normalize consistently without
  inferring an address or overwriting a different pending user choice.
- OpenVPN's `omitempty` serialization discarded `dns: []` and restored a public
  resolver at runtime. The empty list now survives the entire configuration path.
- A fixed updater unit name could collide with an already-loaded transient unit.
  Each attempt now uses a unique unit plus a shared installer lock.
- A timed-out startup could otherwise execute later. The worker now waits for
  acknowledgement before downloading or installing; canceled workers cannot
  overwrite a newer job's state.
- Real systemd expanded variables inside inline shell arguments. The worker
  now runs from a private script, and literal argument dollars are escaped for
  systemd, including older versions without the newer expansion-control flag.
- The old UI retained an indefinite busy state. It now tracks the accepted job,
  handles restarts and terminal failures, and resumes by read-only polling after
  a reload or ambiguous response. It never automatically repeats the update POST.

The actual-systemd tests killed the synthetic launching parent, checked the
worker survived, rejected concurrent workers, preserved a retained failed test
unit, and verified retries after both success and failure. They used only
private paths and fake installers: no live upgrade or external download was
performed by those tests. Live deployment is verified separately after release.

## Scope and limits

All runtime protocol tests used controlled local endpoints in disposable
network namespaces. Public DNS delegation and availability of a chosen external
TLS target remain deployment responsibilities. The standard Orbit TCP path was
exercised; this patch does not claim new live WSS coverage or provision public
outer certificates. Established saved-configuration/export compatibility is
retained. No migration rewrites existing inbounds.

The sole production core change is the OpenVPN server tunnel DNS JSON tag.
Other protocol implementations and the separate client core were not edited.
The previously documented inherited SS2022 UDP dependency race is outside this
patch; passing the panel race suite is not a claim that every core dependency
is race-free.

## Tested executable identities

| Executable | SHA-256 |
| --- | --- |
| `amd64/x-ui` | `fb39bf55ef88526807a28a3457619f2284b1651026da84c26cec234473b2c0b8` |
| `amd64/bin/xray-linux-amd64` | `4ae589216e549efa4a9bcf6587d535eaaae7f98a3542d5a96474779dc9ba6bbc` |
| `arm64/x-ui` | `b8307109d41310ce9a013082f4f5637a4f12eecd606eced14983a3d2b644f868` |
| `arm64/bin/xray-linux-arm64` | `a9ce3c2a3a5d227bd0740ed52e5ff38486ead97fa8d5550761e67de87e972177` |

Archive documentation may be finalized after execution tests; these executable
hashes must remain unchanged. Clean source archives exclude private backups,
credentials, generated binaries, caches and unrelated installers. Licenses and
required test fixtures remain included.

Reproducible test entry points are in `tests/dialect11/`,
`web/service/panel_update_*test.go`, `web/controller/panel_update_test.go`, and
`core/proxy/openvpn/server_config_dns_test.go`. Host evidence is retained in
`/root/x-ui-dialect11-work/explicit-fields-11.5/` and the corresponding agent
reports. Private live-state backups are excluded from all release files.
