# Protocol verification for v2.9.0-dialect.11.10

This release tests the native OpenVPN, AnyTLS, ShadowTLS, DNSTT and Mieru handlers through panel-created inbounds, selected-client JSON export and the panel outbound path. The user's main custom Xray 25.3.6 client source remains unchanged. The client binary was built from its recorded source snapshot; exported configurations are executed without repairing their contents.

The final packaged candidate completed **45 scenario executions with 829 passing runtime/API assertions and zero failed assertions** across the following runs. Repeated configurations on different architectures count as separate executions; these totals include API/export/parser checks as well as actual traffic checks.

| Final packaged run | Scenario executions | Passed assertions | Failed assertions |
| --- | ---: | ---: | ---: |
| amd64 panel/server, unchanged client | 19 | 361 | 0 |
| ARM64 panel/server through QEMU, unchanged amd64 client | 19 | 361 | 0 |
| DNSTT resolver health and healthy controls: 3 outbound-only, 4 client + outbound | 7 | 107 | 0 |

The packaged browser separately passed **18 checks**, parsed copied configurations for all five protocols and reported no console/page errors. It used embedded release assets, without source templates. The final Node suite passed **225 tests**. The client preservation check rehashed **1,520 files**, with no changed, missing or new nonignored files and an unchanged Git HEAD.

The earlier full matrix contains **184 scenarios, 3,252 passing checks and 72 failed checks**. Those are diagnostic results from an earlier candidate, not final acceptance totals. Its failures and the later targeted reruns remain in the detailed report. Some unchanged-client and inherited limitations remain unresolved and are described below; the final passing subset does not erase them.

## Changes verified by this work

- **AnyTLS:** bounded receive backpressure replaces immediate rejection of ordinary upload bursts; a closed logical stream no longer consumes the active-stream limit while its workers finish; independent UDP destinations no longer cancel each other. Resource caps, cancellation and a finite stalled-stream deadline remain enforced.
- **AnyTLS interoperability defaults:** generated/projected server TLS settings use classical curves when the user leaves the curve choice at its default. This avoids a hybrid HelloRetryRequest unsupported by the unchanged client's pinned TLS implementation. Explicit nonempty user choices remain intact; this is not a global TLS default change.
- **OpenVPN:** a slow transport no longer overfills the application output queue and kills a sustained transfer. Application admission yields while retaining control-channel space for rekeying. TLS handshake deadline failures retain a consistent timeout cause. The bundled outbound preserves forced TCP/UDP address-family selection while resolving its server hostname.
- **DNSTT:** the authenticated inner VLESS response header is flushed before waiting for destination application data. Slow DNS uploads to servers that wait for the full request body can therefore complete the client's tunnel handshake. Shared VLESS handler code is unchanged.
- **ShadowTLS:** shared single-user Shadowsocks accounts can be exported, added and renamed correctly; explicit SS2022 managed empty lists remain deny-all. The bundled outbound normalizes inconsistent randomized TLS key-share specifications before applying them, while retaining valid hybrid pairs and ordinary HelloRetryRequest behavior.
- **DNSTT resolver health:** the bundled outbound temporarily excludes failed members, permits one bounded recovery probe after cooldown and ignores stale generation results. A silent TLS handshake is classified by the original operation's timeout, even after cleanup cancels a derived context; caller cancellation does not mark a healthy resolver as failed. Healthy members retain round-robin scheduling; one-resolver behavior is unchanged. It does not replay the same query or add endpoints, direct fallback or TLS bypass. The unchanged client does not receive this scheduler.
- **Panel settings:** native outbound configurations are built and validated before persistence; invalid saves preserve the previous settings. OpenVPN format switching preserves credentials/MTU, DNSTT UDP resolvers expose their supported bootstrap field, Mieru credential limits use UTF-8 byte lengths, and ShadowTLS export trust controls are available. Irrelevant OpenVPN export SNI/CA controls were removed.
- **Outbound measurement:** truncated HTTP bodies fail the probe, temporary idle connections close, and the selected outbound's current settings replace stale copies. A ShadowTLS carrier is tested through one unambiguous associated inner proxy.
- **Shared server TLS certificate safety:** a reproduced reload race required a shared-library correction. Immutable certificate snapshots are published atomically; failed replacement material retains the last working certificate, and invalid timer values are rejected. Certificate file-reading/polling behavior remains supported. This exception is covered by dedicated certificate tests and legacy-protocol regression checks; it is not a change to the main client core.
- **Shared server UDP worker lifecycle:** delayed cleanup only removes the connection generation that it owns, the idle checker remains available for subsequent datagrams, and shutdown rejects post-close connection creation and stops a checker restarted across close. This is a narrow shared-worker exception found during native lifecycle stress; it does not change protocol wire formats. Focused worker and DNSTT concurrent-close tests passed 20 repetitions with the race detector, with independent regression review.

Each fix has a regression test. A test's presence is not itself evidence of a passing release run; final run results identify what was executed.

## Known unchanged-client limitations

**ShadowTLS randomized fingerprints can still fail in the unchanged main client.** Its pinned TLS generator can emit a hybrid key share absent from the advertised supported groups. OpenSSL rejected all 21 malformed specimens in a deterministic 128-specimen set; the other 107 were accepted. The seed persists for the core process, so reconnecting may repeat the failure. A passing randomly selected seed does not establish that the client defect is fixed.

The bundled server outbound correction has separate deterministic ClientHello and complete in-memory handshake regressions. It cannot repair the client's TLS transcript on the server side. Use a fixed compatible browser fingerprint for that client. Explicit fingerprint choices are retained rather than silently rewritten.

A second deterministic reproduction found that a TLS 1.2 CBC encrypted Finished record whose random IV starts with `0x02` can be mistaken for a new ServerHello by the old reader. This corrupts ShadowTLS authentication and can produce `BAD_RECORD_MAC`/EOF. The bundled server implementation is corrected and has complete-carrier regressions, but the unchanged main client retains the old CBC/fragmented-ServerHello reader. Stable strict TLS 1.3 configurations avoid the TLS 1.2 CBC trigger. A successful small sample of TLS 1.2 connections does not remove this intermittent limitation.

Android and 360 presets are TLS-1.2-only in the pinned library. They cannot satisfy strict ShadowTLS v3's TLS-1.3 requirement. Their compatible v2/non-strict-v3 cases and strict-v3 rejection cases are tested separately.

OpenVPN forced-family hostname selection also differs from a literal endpoint: the old bootstrap path collapses `udp6` to generic UDP before resolving the hostname and may select IPv4. The bundled correction passed all four packaged TCP4/TCP6/UDP4/UDP6 hostname cases (77 assertions). The unchanged main client has the same older path; use a numeric IPv6 endpoint when an IPv6-only transport is required. The unchanged exported literal-IPv6 client configuration passed its address-family checks.

## Coverage and interpretation

The finite matrix covers protocol modes, every listed cipher/digest or supported fingerprint class, meaningful combinations, numeric and credential boundaries, export/persistence, authentication rejection, TCP/UDP where supported, byte/hash-verified download and upload, simultaneous transfer, reconnect and selected lifecycle/resource limits. Separate runs cover sustained/concurrent flows, IPv6 destinations, server address families, restoration and native outbound representation modes.

Parser tests, browser form tests, unchanged-client transfers and panel-outbound transfers remain separate evidence categories. An outbound-only setting patch does not alter the copied client profile: its effect is attributed to the panel-outbound column. ARM64 tests execute the packaged panel and server core through QEMU with the same unchanged amd64 client; this verifies server-side ARM64 interoperability, not native ARM64 client execution. Infinite combinations of arbitrary addresses, keys, timing and network failures cannot be exhausted.

All central panel traffic tests use controlled namespace-local endpoints. They do not measure an Iranian ISP, public censorship path, external resolver policy or Internet throughput. The panel latency button measures warm HTTP response-header latency, not ICMP ping or upload/download speed. Historical aborted test invocations are excluded from verification counts and documented in the detailed evidence report.

Important protocol boundaries:

- Stock Xray 25.3.6 was checked first. It rejects these native protocol names. Accepting an ordinary `dns` outbound does **not** prove DNSTT support; the custom nested tunnel configuration is a different feature.
- DNSTT's authoritative listener is UDP. UDP/DoT/DoH are client resolver transports. VLESS inner mode supports TCP and fixed-destination UDP; authenticated SOCKS inner mode is TCP-only. Resolver rotation is not a promise of immediate same-query failover. Public operation needs a real delegated domain supplied by the operator.
- OpenVPN pushed DNS addresses are protocol push metadata and do not automatically configure Xray's DNS client. `remoteCertTls: server` verifies certificate usage, not a hostname. Control wrappers are exclusive, and tls-auth key directions must match the server's complementary direction or be unset on both ends.
- Shared TLS certificate `usage`, `buildChain` and reload behavior have inherited/core tests; they are not all separate unchanged-client traffic scenarios. ECH-required configurations are unsupported by the unchanged 25.3.6 client.
- Legacy AEAD ShadowTLS inner proxies are TCP-only with this client; SS2022 exported clients use UoT v2. SS2022 multi-user ChaCha is unsupported; single-user ChaCha is a separate supported mode.

DNSTT multi-resolver operation also has a confirmed unchanged-client limitation when one configured resolver stops answering. In the controlled two-resolver test, silent requests repeatedly held shared query-concurrency slots until timeout, starving progress despite the healthy resolver answering every request it received. A 32 KiB upload took about 89.5 seconds, followed by application failures. Counting requests to both resolvers was insufficient to prove recovery. The bundled server outbound now applies bounded, generation-aware resolver health selection; all three mixed-resolver cases and four healthy controls passed against the final packaged candidate (107 assertions). Focused silent-TLS, timeout-origin and mixed-transport regressions also passed. For the unchanged main client, use one verified healthy resolver; the authoritative server cannot repair the client resolver scheduler.

OpenVPN UDP has an additional **unresolved unchanged-client stress limitation**. Fresh-session 128 KiB/1 MiB four-stream probes passed, but the repeated 30-second workload still timed out in concurrent and sustained transfers, including a run without half-close. One download stopped at 156,240 of 1,048,576 bytes; later a complete upload submission received no 32-byte acknowledgement. Namespace/socket receive-buffer drop counters increased, but this association does not fully establish causation and local send completion does not prove remote receipt. The bundled outbound passed the corresponding concurrent/sustained checks. No main-client repair is claimed.

## EOF-dependent response limitation

The stress matrix recorded half-close failures. Separate controls sent a complete upload, half-closed the write direction and waited for a response generated only after EOF. Direct TCP succeeded. Stock Xray, the unchanged main client and the bundled core all failed to return that response through SOCKS → freedom, even without a new native protocol. Ordinary echo and complete uploads worked in every control. Stock/main-client targets did not observe EOF before timeout; the bundled-core target observed EOF and sent its response, but that response was not returned to the requester.

These observations do not establish an individual bug in every native protocol. The stress failures remain documented as an EOF-dependent proxy-path limitation; they are not relabeled as successful half-close tests. Ordinary content-length-based transfer checks are separate.

## Broader baseline race limitation

The broad `infra/conf` race run again reproduced the already documented stock SS2022 UDP dependency race in `github.com/sagernet/sing v0.5.1/common/udpnat/service.go`: packet ingestion writes the local address while response handling reads it through `LocalAddr`. The failing test is `TestSS2022StockUDPPacketLifecycle`. This issue predates these changes and is also recorded in [DIALECT11-VERIFICATION.md](DIALECT11-VERIFICATION.md). The dependency and stock SS2022 handlers were not changed here. The failed broad-suite evidence is preserved; do not interpret passing native suites as a clean pass for every race test in the repository.

## Final executable identities

These SHA-256 values identify the actual packaged executable bytes, not the ARM64 QEMU launcher scripts. All four were rehashed after testing and matched their pre-test bytes. The detailed report lists launcher identities separately.

| Executable | SHA-256 |
| --- | --- |
| amd64 panel | `971d72ae4da5d501e302a4dcb24912107aa0cb18ec5fe24b48f5f4af3d0703ef` |
| amd64 server core | `377f0aa41dcca3c4f40e52540788184626ed1adde879ce9d2657017ec369e588` |
| ARM64 panel | `67316ae3032b002be9695af4d5cc266e210c33d9f9fa4f8970f834649fc46c05` |
| ARM64 server core | `c70a437eb0faebb68a8c9f0c07e4ec05bbbdcee6ab5fad7fe1e05555a572a1fa` |

## Reproduction

Run from a disposable checkout with the matching toolchains/dependencies installed. Keep generated credentials and disposable databases outside the source tree. Set `LAB` to the verification artifact directory, `PANEL_BINARY` / `SERVER_CORE` to the packaged candidate executables, and `CLIENT_CORE` / `STOCK_CORE` to the recorded immutable binaries. The runner and manifests are included under `tests/dialect11` in the clean source archive; `LAB` is only a disposable output directory.

```sh
# Panel model and workflow tests.
node --test tests/dialect11/*.test.js

# Focused parser matrix; parser success is not connectivity proof.
(cd core && unshare --net env GOPROXY=off GOSUMDB=off go test ./infra/conf \
  -run '^(TestDialect11(AnyTLS|ShadowTLS).*Matrix|TestDialect11ShadowTLSManaged2022Modes|TestDNSTTInbound.*OptionMatrix|TestMieruMatrix.*|TestTLSCertificateOCSPIntervalBoundaries)$' -count=1)

# Real socket package tests remain in an empty network namespace.
(cd core && unshare --net bash -euc '
  ip link set lo up
  export GOPROXY=off GOSUMDB=off GOMAXPROCS=3
  go test -race -p 1 ./proxy/openvpn/... ./proxy/anytls/... ./proxy/shadowtls/... \
    ./proxy/dnstt/... ./proxy/mieru/... -count=1 -timeout=20m
  go test -race -p 1 ./transport/internet/tls -skip "^TestECHDial$" -count=1 -timeout=20m
')

# Panel-created profiles, unchanged client JSON and panel outbounds.
python3 -B tests/dialect11/protocol-matrix.py \
  --repo "$PWD" --panel "$PANEL_BINARY" --server-core "$SERVER_CORE" \
  --client-core "$CLIENT_CORE" --stock-core "$STOCK_CORE" \
  --work "$LAB/private/reproduction" --netns \
  --manifest tests/dialect11/protocol-matrix/openvpn-runtime.json \
  --manifest tests/dialect11/protocol-matrix/anytls-runtime.json \
  --manifest tests/dialect11/protocol-matrix/shadowtls-runtime.json \
  --manifest tests/dialect11/protocol-matrix/dnstt-runtime.json \
  --manifest tests/dialect11/protocol-matrix/mieru-runtime.json

# Package both release architectures; output directory is disposable.
ARCHES='amd64 arm64' OUT="$LAB/reproduction-dist" GEO_SRC="$GEO_FILES" ./build.sh
```

Browser fixture tests use repository templates and a locally installed Playwright/Chromium. The packaged-browser run separately uses the release executable's embedded assets without source templates: all five protocols rendered and all five copied client configurations parsed, with 18 browser checks and no console or page errors. The main client file manifest and each executed binary hash are checked separately. Optional upstream-reference tests requiring external binaries are reported as skipped when those binaries were not supplied. `TestECHDial` requires an external service and is excluded explicitly from the isolated TLS suite; it is not counted as a pass.

The detailed report is generated by `tools/summarize-results.py` in the laboratory artifacts. It preserves earlier failures, shows which later named reruns resolved them, distinguishes unsupported or unrecorded cases, and excludes private configurations and credentials. No production deployment or live Iranian-network test is claimed by this document.
