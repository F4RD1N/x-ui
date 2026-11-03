# Real panel and core integration tests

Run this harness with freshly built panel and core binaries. It creates a new Linux network namespace with loopback and one benchmark-range address (`198.18.0.1/32`), a private database, synthetic certificates, local HTTP/TLS/UDP services, and actual panel/core processes. It never contacts a provider or uses installed databases, keys, credentials, firewall rules, or service units. Root or equivalent namespace privileges are needed. Dependencies: Python 3 with `requests`, OpenSSL, curl, iproute2, and util-linux `unshare`.

```sh
tests/dialect11/run-panel-e2e.sh \
  --panel /absolute/path/to/x-ui \
  --core /absolute/path/to/xray-linux-amd64 \
  --expect-reload --isolation-lifecycle \
  --work /absolute/path/to/new-empty-test-directory
```

The work directory must not exist. It retains logs, freshly generated test credentials, exported configurations, a backup, and `results.json`, all under restrictive permissions. Keep these generated artifacts outside source archives. Nonzero exit means a failed assertion or incomplete run. `--only` filters cases for diagnosis and must not be used for a complete release result.

The test creates and edits each inbound through authenticated HTTP endpoints, edits native clients through path-safe identities, exports actual JSON subscriptions, and runs the exported protocol settings in real core clients. It exercises TCP payloads and supported UDP payloads through both the panel-managed inbounds and panel-managed native outbound templates. It then downloads a portable backup, rejects a damaged backup while checking live traffic remains available, stops the first installation, removes its referenced certificate files, restores into a fresh installation, checks remapped private file permissions, and repeats traffic. With `--expect-reload`, it also verifies automatic panel/subscription reload, changed listener ports and base paths, preservation of an explicitly stopped core, and successful traffic after an explicit restart.

Encrypted SS2022 cases additionally verify per-user routing (one account denied while the other forwards) and TCP bodies above 1 MiB.

With `--isolation-lifecycle`, bounded malformed input is sent to each native listener while verifying the same core PID and stock VLESS traffic remain healthy. Each native account is then revoked through the HTTP client API, replaced with fresh credentials, and re-enabled; old credentials must fail while new TCP/UDP and outbound traffic succeeds.

The 23 cases cover:

- AnyTLS normal and UUID middle-hash authentication.
- Mieru TCP, UDP, and UUID metadata mode.
- DNSTT with VLESS and authenticated SOCKS inner protocols.
- Orbit TCP, WebSocket, and QUIC.
- ShadowTLS v3 normal and required UUID session ID carrying VLESS; encrypted AEAD and SS2022 inner protocols, including multiuser key selection and UDP over TCP v2.
- OpenVPN TCP, UDP, and TCP with required client proof.
- VLESS stock and dialect 120; VMess stock and raw UUID authentication; Trojan stock and UUID prefix authentication.

DNSTT's SOCKS inner protocol deliberately supports TCP only, so its UDP test is omitted. This finite suite does not claim all possible networks or transport combinations; protocol-specific unit, race, independent-peer, negative-authentication, rekey, and transport tests supplement it.

Use `--client-core /absolute/path/to/reference-core` to test a separate existing client build while the candidate core remains the server. Raw panel fixtures contain actual ports and UUIDs, so the harness sets the existing `xray.endpoint.mapping=off` client switch to disable provider-specific reversible endpoint normalization. This does not patch the client. The benchmark-range target also avoids older OpenVPN client stacks' intentional rejection of loopback packets.

For explicit QEMU execution without installing host binfmt handlers, pass executable shell wrappers as `--panel` and `--core`, each running the corresponding ARM64 binary through QEMU, and select `--panel-arch arm64`. Wrapper target paths must be absolute. The panel then finds the core wrapper under the correct architecture-specific filename in its private binary directory.
