# Dialect11 release verification

For the subsequent `2.9.0-dialect.11.1` UI correction, see
[DIALECT11-HOTFIX.md](DIALECT11-HOTFIX.md). Panel hashes below describe `.11`;
the core executables are unchanged in `.11.1`.

Verification recorded on 2026-11-03 for `v2.9.0-dialect.11`. Native component, panel, current-client interoperability, Linux AMD64/ARM64 and AMD64 Docker checks passed within the scope below. One independently reproduced inherited SS2022 dependency race remains explicitly documented.

## Baseline and delivered scope

The baseline is released `2.9.0-dialect.10` (`08976a6`) plus `c02848d`, which adds VLESS minimum/maximum client-version controls. The bundled server remains based on Xray **26.3.27**; the independent compatibility client is the current customized **25.3.6**, built without modifying its source. This is not the separate multi-instance branch.

All six protocols have native Go inbound and outbound handlers inside Xray: **Orbit, DNS tunneling/DNSTT, OpenVPN, AnyTLS, ShadowTLS and Mieru**. Production requires no separately installed protocol daemon, plugin, adapter executable or shared library. The panel creates their inbounds, edits server outbounds, preserves advanced settings, exports selected-account JSON and applies normal Xray routing/accounting.

Configuration and deployment requirements: [DIALECT11.md](DIALECT11.md). Test harness: [tests/dialect11/panel-e2e.md](tests/dialect11/panel-e2e.md). OpenVPN server schema: [core/proxy/openvpn/NATIVE_SERVER.md](core/proxy/openvpn/NATIVE_SERVER.md).

Optional authentication flags remain off by default: VMess `rawUuidAuth`, OpenVPN `clientProof`, AnyTLS `uuidHashMiddle`, ShadowTLS v3 `requireUuidSessionId`/`uuidSessionId`, Mieru `uuidMetadataTrailer`, Trojan `uuidHashPrefix`, and SS2022 `uuidIdentityKeys`. Standard and custom modes, rejection paths, account updates and persistence have dedicated tests. SS2022 UUID handling normalizes identities into existing cipher keys; it does not introduce a new cipher.

Native typed account APIs are used where supported. DNS/ShadowTLS changes that require complete inner policy request a reload; unsupported operations do not report false success. Disabled/expired users are filtered, empty native listeners fail closed, selected-account exports omit server secrets, and unsupported URI/Clash combinations explicitly require JSON.

The authenticated credential helper generates DNSTT/Orbit/OpenVPN material with bounded strict JSON, sanitized errors and `Cache-Control: no-store`. It does not save generated secrets. Its read-only review found no high/medium issue; service and controller tests passed with the race detector.

## Real panel, core and current-client traffic

| Final run | Result | Evidence |
| --- | --- | --- |
| AMD64 candidate v3, current unchanged 25.3.6 client | **251 checks passed, 0 failed, 23 configurations; completed=true** | `/root/x-ui-dialect11-work/e2e-final-v3b/results.json` |
| ARM64 release panel/core under QEMU, current 25.3.6 client | **92 runtime checks passed, 0 failed, 9 representative cases** | `/root/x-ui-dialect11-work/arm64-release-runtime-final/panel-e2e/results.json` |
| ARM64 parser against all final exports | **23 configurations passed** plus fixture-count check | `/root/x-ui-dialect11-work/arm64-release-parser-final-v3b/results.json` |
| ARM64 combined architecture/runtime/parser manifest | **36 wrapper checks passed, 0 failed**; overlaps the rows above | `/root/x-ui-dialect11-work/arm64-release-runtime-final/final-results.json` |

The AMD64 matrix covers normal/custom AnyTLS; Mieru TCP/UDP/custom metadata; DNSTT inner VLESS/SOCKS; Orbit TCP/WS/QUIC; ShadowTLS v3/custom session plus encrypted AEAD and SS2022/UoT; OpenVPN TCP/UDP/proof; stock VLESS/VMess/Trojan; VLESS dialect 120; raw-auth VMess; and custom-prefix Trojan.

Tests use real authenticated panel HTTP creation/edit/export, native client edits, unchanged exported protocol objects, actual TCP content and supported UDP payloads, and real server outbound forwarding. Each native protocol receives malformed input, then disable/rotate/re-enable/revoke tests; the core remains alive and stock VLESS still forwards. Encrypted ShadowTLS checks exceed 1 MiB, select the correct inner user's key, and prove one user's routing denial does not affect another.

The existing client's default endpoint mapping must be disabled for raw exported endpoints with its existing `xray.endpoint.mapping=off` setting/app wrapper option. This is configuration, not a client source patch. OpenVPN targets use an owned benchmark-range address inside the namespace because the older client stack rejects loopback traffic.

The new-protocol and panel integration used disposable private namespaces, synthetic credentials and owned local endpoints. No provider API/configuration, production database or host firewall was used. The broader legacy core suite also includes existing public DNS/HTTPS checks. QEMU validates ARM64 userspace execution on an AMD64 host, not physical ARM hardware, its kernel or throughput.

Detailed evidence: `/root/x-ui-dialect11-work/agents/panel-http-e2e-report.md` and `/root/x-ui-dialect11-work/agents/arm64-release-verification.md`.

## Backup and restoration

Portable ZIPs contain a consistent SQLite snapshot, manifest hashes and referenced TLS/key assets; inline native settings, optional flags, routing and outbound templates stay in SQLite. Legacy SQLite imports remain supported. Restore validates schema/assets/core configuration before replacement, installs assets under private managed paths, preserves the predecessor until startup succeeds, and rolls back failed transactions.

The scoped five-package backup/restore race suite passed **95 test/subtest events**, with zero failures/races. It covers WAL snapshots, concurrent mutation admission, malformed/traversal/duplicate/missing assets, keypairs, strict migration, nine injected destructive-boundary failures, rollback, publication and listener ownership. A separate final asset utility race check also passed.

Real AMD64 and ARM64 runs downloaded backups, rejected missing assets without stopping traffic, deleted original TLS files, restored into a fresh database, verified remapped mode-0600 assets and unchanged exported credentials, and repeated traffic. They also checked automatic panel/subscription listener reload, changed paths/ports, occupied-listener rejection, preserved stopped-core state and successful explicit restart.

Evidence: `/root/x-ui-dialect11-work/agents/portable-backup-tests-final.jsonl`, `/root/x-ui-dialect11-work/evidence/portable-assets-final-race.log`, and the final E2E manifests above. Backups contain private keys and require private storage; remote DNS delegation, domain ownership and public certificate issuance are deployment prerequisites.

## Panel, frontend and optional-auth regression

| Scope | Completed result | Evidence |
| --- | --- | --- |
| Uncached full panel module, default vet | 9 packages passed; 339 pass events/140 top-level tests; 18 packages have no tests | `/root/x-ui-dialect11-work/agents/final-panel-suite-report.md` |
| Sole panel skip: real geosite files | Passed separately on default/IR/RU assets, including 70 MiB RU; original/lowercase forms | `/root/x-ui-dialect11-work/agents/geosite-local-assets-final.log` |
| Credential helper/controller | Focused race checks passed; reviewed source hashes unchanged | `/root/x-ui-dialect11-work/agents/native-credentials-focused-race-final.log` |
| Inbound model and legacy serializers | 110 grouped checks passed | `/root/x-ui-dialect11-work/evidence/frontend-inbound-final.log` |
| Outbound models and restore UI | 45 tests passed; no skips/failures | `/root/x-ui-dialect11-work/evidence/frontend-outbound-restore-final.log` |
| Real-template Chromium, desktop/mobile/dark | 18 inbound and 16 outbound scenarios passed; zero page errors | `/root/x-ui-dialect11-work/evidence/frontend-inbound-browser-final.json`; `frontend-outbound-browser-final.json` in the same directory |
| VMess/Trojan parser/auth and native account API | Race checks passed; actual TCP/UDP and mixed/custom rejection coverage | `/root/x-ui-dialect11-work/agents/auth-parser-race-final.log`, `trojan-runtime-race.log`, `vmess-raw-evidence/server-focused-race-test.log`, `native-protocol-api-race.log` |

The panel suite source snapshot was recorded at **2026-11-03T01:14:29.332567Z**. Only a non-Go Docker test changed during it; Go/module/frontend hashes were unchanged. Later final Mieru callback guards have their own complete race/reference run and are in candidate v3. The nested core module is not implicitly tested by panel `go test ./...`.

Browser submit/credential responses are controlled fixtures; live backend behavior is established by separate HTTP/E2E checks. Ten legacy inbound fixtures and all eleven existing default outbound serializers were checked for preservation. Counts across suites or reruns overlap and are deliberately not added into a grand total.

## Native component and independent-reference checks

| Component | Authoritative completed final evidence |
| --- | --- |
| AnyTLS | Complete package race/reference pass, 11.394s: native outbound to upstream v0.0.13 server and independent sing-anytls v0.0.11 client to native inbound TCP/UDP; routing, custom auth, TLS and lifecycle. `/root/x-ui-dialect11-work/agents/anytls-final-race-tests.log` |
| Orbit | Root package race pass 24.518s; internal transports 15.820s. TCP/QUIC/WS/WSS/TCP-Reality, bulk TCP, UDP, trust failures, routing/accounting, generation-safe revocation and shutdown. `/root/x-ui-dialect11-work/agents/orbit-native-race-final.log`; `orbit-transport-race-final.log` in the same directory |
| DNSTT | Final native/fixture race passes 104.102s/1.028s; parser 1.233s; 48 top-level functions and 24,903 bounded fuzz executions. Independent current-client, UDP/DoT/DoH, 1 MiB, multiplexing, controlled loss, rejection/recovery and stock-DNS preservation. `/root/x-ui-dialect11-work/agents/dnstt-verification.json` |
| Mieru | Final v3 race/reference pass 68.394s; 59 top-level groups/174 test events. Both underlays/directions against official client 3.34.1 and Mita 3.34.1/3.38.1, bulk/stalled-reader traffic, final callback guards and routing. `/root/x-ui-dialect11-work/agents/mieru-final-v3-race-interop.log` |
| ShadowTLS | Final native wire/reference race pass 16.234s; integration/config 11.340s, after shared bridge correction. Versions 1/2/3, official servers and separately baselined reference client, eight encrypted-inner modes, UoT v1/v2, routing and cancellation. `/root/x-ui-dialect11-work/agents/shadowtls-final-fixed-integration-race.log` |
| OpenVPN | Final glue/private-stack race pass, main 95.569s; routing/clock 20.190s; engine 6.705s and wrappers 4.409s. Stock client→native server, TCP/UDP and wrappers, TUN/rekeys; native outbound→11 stock profiles, compression/ciphers, delayed FIN and bulk transfers. `/root/x-ui-dialect11-work/agents/openvpn-final-verification.md` links individual final logs |

The shared packet bridge had a reproduced cache ownership/close race and late-result leak. Its narrow correction changes `core/common/singbridge/packet.go`, not SS2022 framing/handlers. Ten regression groups plus two subtests passed five race-enabled repetitions; final ShadowTLS consumers also passed. Evidence: `/root/x-ui-dialect11-work/agents/singbridge-packet-ownership-fix.md`.

Protocol handlers/parsers and tests are isolated by protocol, with necessary additive registration, panel/account/export/backup integration. Requested optional VMess/Trojan paths and an OpenVPN mux-context lifecycle marker are explicit existing-code changes; this is not a claim that every shared source file is untouched.

## Confirmed inherited issue that remains

**The stock SS2022 UDP path still has a data race in existing `github.com/sagernet/sing v0.5.1/common/udpnat/service.go`.** Packet ingestion writes `c.localAddr` at line 92 while response handling reads it through `LocalAddr` at line 155. The seven-mode real UDP/lifecycle functional test passed, but its race run failed. A separate module importing only official sing v0.5.1, with no Xray or packet bridge, independently reproduced the same race.

The baseline already pins this dependency. Stock SS2022 handlers/dependencies were intentionally not modified in this isolated-feature release. Synchronizing the mutable address while retaining NAT rebinding is the scoped follow-up. Do not describe all race gates as passing. Evidence: `/root/x-ui-dialect11-work/agents/ss2022-stock-udp-regressions.md` and `ss2022-inherited-udpnat-race.log` in the same directory.

## Compatibility and untested limits

- **Orbit QUIC:** inherited Initial trailer exposes recoverable bearer credentials outside QUIC protection. Server pinning does not fix this; use TCP/WS/WSS/TCP-Reality for protected native authentication. Compatible QUIC requires a stable UDP tuple; WSS outer trust is separate from the inner pin.
- **Mieru UDP:** inherited metadata/payload seals reuse an AEAD key/nonce within a datagram, independently confirmed in the reference. Fixing the wire format requires both peers. TCP is the default underlay and can carry UDP destinations. The additional real-Mita 3.38.1 UDP test passed after 75 seconds idle and a forced server sweep, with traffic in both directions and zero races (80.068 seconds total). Evidence: `/root/x-ui-dialect11-work/agents/mieru-stock-idle-soak.md`. Continuous or unlimited-duration testing is not claimed.
- **ShadowTLS:** the carrier does not encrypt post-handshake payload. Plain inner SOCKS/VLESS needs application TLS or an encrypted inner protocol; supported Shadowsocks/SS2022 provides payload encryption. Reverse reference testing used a documented test-only parser correction after validating the reference against the official server.
- **OpenVPN native server:** TUN/TLS, TCP/UDP and optional proof are supported. TAP, non-TLS static-key mode, server compression, seamless UDP rebinding and arbitrary remote ICMP forwarding are not implemented. Gateway ICMP is local; existing outbound compression/profile behavior is separate.
- **DNSTT:** production requires delegated DNS and resolver reachability; authoritative service uses UDP. Public censorship/Iran reachability was not tested. Inner SOCKS supports authenticated TCP only; inner VLESS carries TCP/UDP. Ordinary DNS without a tunnel remains stock DNS.
- **Authentication:** VMess raw UUID is compatibility, not stronger protection; outside protected transport the clear UUID also exposes its header key. Other compatibility flags likewise do not automatically improve security.
- Finite local tests do not prove every network condition, mobile handover, physical ARM platform, endless load or absence of future defects. Broad-run opt-in skips remain recorded even when exact independent-reference tests passed separately.

## Complete-module regression and corrected fixtures

An initial AMD64 v3 E2E attempt correctly rejected an SS2022 fixture with an invalid per-user method. Only the fixture was corrected to inherit the top-level method; unchanged production binaries then passed all 23 cases in v3b. ARM runtime had already passed; only the affected 23-export parser phase was repeated. Earlier failed attempts remain preserved, not counted as successes.

The broad core run encountered two test-environment failures: a missing inherited `common/buf/data/test_MultiBufferReadAllToByte.dat` fixture and `common/platform` expectations affected by a global asset-path override. The byte-identical upstream fixture was restored (2,319 bytes, SHA-256 `0414d4b26cab725ef45fd9ece8fdf66597683202e6d6b08b3f3dc8dcae7a6752`); focused complete buf/platform race reruns with asset overrides removed passed **35/35 cases, with no failures, skips or races**. No protocol logic changed for these corrections.

The complete core sweep recorded **111 passed packages, 3,755 passed named cases, 23 explicit skips**, and the two setup failures above; 93 packages contain no tests. Its original exit status remains 1 in the preserved log. The successful full-package corrective reruns cover both failed packages. This broad sweep used `-count=1` without `-race`; focused race runs are identified separately. Three source/test paths changed during the sweep (Mieru callback guards and the added stock SS2022 regression); their final focused evidence is recorded above. Report: `/root/x-ui-dialect11-work/agents/full-core-regression.md`; machine result: `/root/x-ui-dialect11-work/core-regression/summary.json`. The skip audit at `/root/x-ui-dialect11-work/core-regression/skip-coverage-review.md` predates the later successful Mieru idle soak; primary skips remain skips, even where supplemental tests passed. Remaining unrun opt-ins include legacy external ICMP peers, SO_MARK and separate legacy OpenVPN fault/plugin harnesses. No unresolved functional regression was found in this combined coverage; the inherited SS2022 race is a separate unresolved finding.

Docker packaging passed 16 targeted checks, including a real scratch-context build/export. The complete **linux/amd64 image then built and passed 9 runtime checks**: native/legacy parser matrix, versions/notices, actual entrypoint HTTP, fresh SQLite login and authenticated portable backup. The container had no network, published ports, privileges or capabilities and was removed. The local image `x-ui-dialect11-review:20261103-native` has ID `sha256:49797721f855b4cbd0adef9c12da8c81e5160bc4b43c22b02179f3d9c8b2a44c`; it was not pushed or deployed. ARM64 Docker was not built; ARM64 Linux release/QEMU verification is separate. Evidence: `/root/x-ui-dialect11-work/agents/docker-packaging-verification.md` and `/root/x-ui-dialect11-work/agents/docker-runtime/results.json`. Two initial runtime-harness expectation/copy errors were corrected without changing source or image; no traffic coverage is inferred from these smoke checks.

## Tested binary identity and reproducible source

Source snapshot: `/root/x-ui-dialect11-work/evidence/candidate-v3-source-manifest.json`, recorded **2026-11-03T01:20:26.220625Z**. Its SHA-256 is `c8f0223ca6c432cbbe509f393a2dcae07bfc1acbe8a0df71621ab30c0a8c9b62`.

| Tested executable | SHA-256 |
| --- | --- |
| AMD64 panel | `981eb43d720ea6fe9d15391ef55e8eaf9ba818aacf08966c53859561abb6dbc9` |
| AMD64 server core | `eedc29ec3176743533e489b00914e3435c9d8c11e05d1ef3b2bdfac4b1a6d3cd` |
| ARM64 panel | `bf66841ee5b403e5060ffffa07ff66ea4f94db8969573edc37ce4da11dd6c20f` |
| ARM64 server core | `87fe205bc66d3f786b3ebbb8632b2761f1561beb72aa101f8d67cb23393a6af2` |
| Unmodified-source 25.3.6 compatibility client build | `ed25817643a397be243e090a44d9ea01a70f6b87c184616d8acaa60ddcd75261` |

These hashes identify both the executed v3 binaries and the clean rebuild from implementation commit `cb0210ffcf6f6d82f08938bc161b4ae38f2cc58d`. The rebuild used a Git archive, Go 1.27.0, `-trimpath`, the repository build script and existing public geo assets. All four rebuilt executable hashes matched the tested binaries exactly; see `/root/x-ui-dialect11-work/evidence/release-executable-verification.json`. Final archive hashes are provided separately in `SHA256SUMS`; adding this verification document to the bundles does not change their executable bytes.

Clean source delivery excludes live API credentials, private delivery configuration, databases/backups, runtime certificates, caches, generated build directories/binaries and unrelated files; built outputs are separate. Synthetic test fixtures and required license/provenance notices remain. Runtime bundles include panel/core licenses and dependency texts; see [core/licenses/NATIVE-PROTOCOLS.md](core/licenses/NATIVE-PROTOCOLS.md). External reference executables/emulators and their private test directories are not runtime dependencies or clean-source payloads. Source delivery is exported from tracked Git files, retains the required small buffer test fixture, and excludes the unrelated Windows installer through `.gitattributes`. Source scanning found no delivery bot credential or JWT credential in the additions; private-key marker matches were reviewed synthetic tests. Original main, dialect10 and client trees remain unchanged.
