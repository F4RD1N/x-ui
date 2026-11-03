# Native inbound defaults — dialect11.2

Selecting a new Orbit, DNS tunnel, OpenVPN, AnyTLS, ShadowTLS or Mieru
inbound generates fresh credentials and required cryptographic material. Long
protocol explanations have been removed from the forms. Existing configurations
are preserved when opened for editing, cloned, or restored.

## Generated profiles

| Protocol | Default profile |
| --- | --- |
| Orbit | TCP, a fresh inner certificate and private key, and a client connection key bound to that certificate. |
| DNS tunnel | Fresh X25519 key pair, a unique tunnel name, and an inner VLESS account. The export connects directly to the inbound address and UDP port. |
| OpenVPN | UDP, a private CA, distinct server and client certificates and keys, AES-GCM data ciphers, and TLS-crypt-v2 control keys. |
| AnyTLS | TCP with TLS, a fresh certificate and key, client password, and public CA trust in the client export. |
| ShadowTLS | Version 3 with a configurable TLS cover endpoint and an encrypted SS2022 inner proxy with separate server and client keys. |
| Mieru | TCP with a fresh username and password. |

Values are generated on demand, not copied from a shared example. Certificate
validation remains enabled. Certificates use the requested panel hostname or
IP address, with the matching public name and trust exported to clients.
Orbit's direct transports verify a numeric server IP. Their generated
certificate includes the selected server IP, and the export retains that same
address. When the panel is opened by hostname, generation resolves it to an IP;
an explicitly configured server address takes precedence. A panel behind a CDN
or another forwarding service may need its actual VPN server IP selected.

Generated leaf certificates last one year, bounded by the issuer's lifetime;
generated CAs last ten years. Existing credentials are not automatically rotated
when a form opens. Operators still need to renew certificates before expiry.

## Additional clients and private material

OpenVPN retains its CA signing key in private panel metadata so additional
clients can receive their own certificates without rotating the CA or existing
accounts. The metadata is removed from the server core configuration. Subscriber
exports select only public server parameters and that subscriber's credentials;
they do not receive the CA signing key or server private key.

Private panel backups preserve issuer material together with the settings,
allowing client issuance after restore. Treat these backups as secrets.
Existing imported OpenVPN deployments that lack their CA signing key cannot
issue new certificates automatically without supplying the matching issuer.
They are not silently replaced by another CA.

## DNS and deployment choices

The default DNS tunnel name ends in `.tunnel.invalid`. It is used between the
direct client and server and does not claim an actual public DNS delegation.
The client export derives its resolver address from the current inbound address
and port, so changing the listen port does not leave an obsolete generated
resolver address behind. To use public recursive resolvers, configure a domain
you control with the appropriate delegation and specify those resolvers.

The ShadowTLS cover endpoint is editable and must be reachable from the server.
Certificate generation cannot provision DNS records, firewall access, public
domain ownership or third-party endpoints. These remain deployment choices.
Optional Orbit WSS still requires an outer certificate trusted by the client:
the existing client has no setting to import a generated outer CA. Default
Orbit TCP uses its generated pinned inner certificate and requires no public
certificate issuance. Switching to Reality fills missing keys without rotating
existing account credentials; its cover endpoint remains configurable.
Plain Orbit WebSocket can use an internal DNS-form HTTP Host when the panel is
opened by IP; the exported dial endpoint and inner certificate identity keep
the original IP. This does not require public DNS. WSS instead needs a Host
matching its trusted outer certificate.

## UI lifecycle

Generation applies only to a new protocol selection. A response from an older
selection cannot replace the current form. Closing the form cancels pending
generation, and changes made while it is running are preserved. Saving waits
for credential generation to finish. Existing inbounds and backup restores do
not regenerate credentials merely because the editor is opened.

This patch also includes the complete Inbounds page and outbound Save-button
fixes documented in [DIALECT11-HOTFIX.md](DIALECT11-HOTFIX.md).

## Additional defects found by the checks

Adding a ShadowTLS client now adds its matching inner account in the same
validated update. Renaming its email preserves the matching inner binding and
the existing keys. Unrelated users and server settings are retained. Explicit
AnyTLS CA bundles are filtered to public certificate blocks before export, so
an accidentally pasted private PEM block cannot reach subscribers.

Native client serialization converts an empty Telegram ID to numeric zero and
valid decimal IDs to numbers before saving. Invalid values remain visible and
fail validation. This fixes the backend's rejection of the browser's former
empty-string value without changing the shared legacy client model. The final
patch version changes asset URLs, invalidating cached interim JavaScript.

Longer OpenVPN sessions exposed a timer publication race in the new server
handler's private network stack. The filter timer now waits until initialization
is published, and shutdown releases waiting callbacks without running them.
This is confined to the bundled OpenVPN server implementation; other protocol
handlers and the separate custom client core are unchanged.

## Verification

Verified on 2026-11-03 for `2.9.0-dialect.11.4`:

| Check | Result |
| --- | --- |
| Complete panel Go module under `-race` | 472 named test/subtest passes, zero failures. The one opt-in geodata case skipped here passed separately against installed assets in 82.992 seconds. |
| AMD64 generated-profile traffic | 141 checks passed, zero failures, using the unchanged custom 25.3.6 client and the final server core. |
| ARM64 runtime matrix under QEMU | 177 checks passed, zero failures on the `.11.2` runtime candidate; actual ARM panel/core execution, not only cross-compilation. Final browser corrections preserve the same backend and core. |
| Final `.11.4` ARM64 artifact checks | 39 checks passed: exact hashes/version, unchanged tested core, all six authenticated generate/save/export flows, ARM parsers, and all three served native scripts matching final source and cache version. |
| Complete-page independent browser review | 43 broad groups plus final focused mode/input checks passed, zero Vue errors; the broad run made 55 calls to the real credential generation service. |
| Exact browser save requests against real panels | 60 checks passed across 12 Create/Add Client and Create/Clone scenarios for all six protocols, without repairing captured request bodies. Saved subscriptions and core parsing passed. |
| Final Orbit WebSocket gate | All ten exact browser mode fixtures export and build; inner certificate identities match. The unchanged client also carries HTTP over 1 MiB and UDP from an exact saved browser-generated WS profile (4 checks passed). |
| Existing and new browser regression suites | Inbound editor, outbound real Save clicks, complete Inbounds page, and automatic profile creation all passed. |
| OpenVPN private timer/native runtime race checks | Passed in 25.142 seconds, including the real first maintenance tick and shutdown. |
| Generated OpenVPN stock/native runtime checks | Passed under `-race` in 9.460 seconds, including subsequent client issuance and optional proof. |
| Live installation | Both existing inbounds render, all six unsaved default/additional-client forms pass, panel/core are running, existing IDs and settings are preserved. |

The traffic matrices cover initial and second accounts, wrong-secret rejection,
HTTP transfers over 1 MiB, UDP payloads, native server outbound reuse, portable
backup/restore, and issuing a third OpenVPN client after restore from the saved
CA. ARM verification also parses all 13 raw exported client configurations and
checks both database copies for integrity. ARM tests used QEMU, not physical
ARM hardware.
Final archive documentation was refreshed after these checks; panel and core
executables remain byte-for-byte identical to the tested hashes below.

Browser tests cover protocol changes, pending requests, timeout/retry, malformed
responses, preserving manual edits, ordinary protocol isolation, additional
clients, actual clone submissions and optional transport changes. Dormant
Orbit mode material remains in form memory while inactive fields are omitted
from runtime JSON; Reality and WebSocket mode round trips pass actual core
parsing. The complete-page review uses the production credential service with
controlled persistence responses; the separate real-panel traffic tests cover
database persistence and restore.
The exact-request replay additionally closes the gap between browser model
validation and the backend's typed client schema. A DOM test confirms invalid
Telegram IDs neither trigger a save request nor cause a rendering exception;
corrected IDs submit as numbers. The native helper/metadata/mode suites pass
62 groups, with 110 inbound-model checks and the existing legacy regression
checks also passing.
The WSS fixtures verify parsing, inactive-mode preservation and inner
certificate identity. They do not demonstrate outer WSS certificate trust or
live WSS traffic; a trusted certificate matching Host is still required.

The generated-profile tests use owned local endpoints in isolated network
namespaces. ShadowTLS uses a controlled TLS cover with its test CA trusted
through the test environment, never a disabled verification option. Separately,
the default Microsoft cover endpoint completed a verified TLS 1.3 handshake
from the deployment host. This does not guarantee every future network path
or third-party endpoint will remain reachable.

The live browser check created no test inbound records. It generated forms and
additional accounts without saving them; before/after configuration hashes
match. A pre-existing missing-resource HTTP 404 remains; there is no Vue
rendering exception and the complete Inbounds table is visible. The previous
panel/core executables and a consistent SQLite backup remain private on the
deployment host and are excluded from release artifacts.

### Executable hashes

| Executable | SHA-256 |
| --- | --- |
| AMD64 panel, installed live | `a08006d0c62410fe23b0812fbdd0e8dcbd4d3ad044260c6bc8113b29c6119d06` |
| AMD64 core, installed live | `fa242d56739a8b79d70865467dee5dc658ca92e92f25b8d4ea0bd04f358ccde9` |
| ARM64 panel | `ea06d14897289c5c5f4fa3079c9a65c39ed8e209f1c2f5be2c8879b2e347407e` |
| ARM64 core | `1d530fdbf593e14b672527d8413ea89dba0ef164140c3f09c3604ae364e9577c` |

The original `/root/x-ui`, `/root/x-ui-wt/dialect10` and separate client-core
source trees were not edited. In this working tree, the only core implementation
changes since `.11.1` are the private OpenVPN timer publication barrier and its
activation call; the third changed core file contains regression tests.

Reproducible test entry points are in `tests/dialect11/`, including
`run-default-profiles-e2e.sh`, `inbound-native-defaults-ui.js`,
`native-defaults-review-ui.js`, `native-creation.test.js` and
`native-modes.test.js`. `replay-browser-native-posts.py` and
`native-orbit-browser-traffic.py` exercise real persistence and exact browser WS
traffic. Host evidence is under
`/root/x-ui-dialect11-work/automatic-defaults/`,
`/root/x-ui-dialect11-work/default-profiles-e2e/v2b/` and
`/root/x-ui-dialect11-work/agents/automatic-defaults-review/`, including
`real-persistence-final/`, `orbit-final-v7/` and
`orbit-ws-real-traffic-final/`.

Earlier protocol compatibility limits, including the inherited stock SS2022
UDP dependency race, remain documented in [DIALECT11.md](DIALECT11.md) and
[DIALECT11-VERIFICATION.md](DIALECT11-VERIFICATION.md). This patch's focused and
integration checks do not imply a new exhaustive full-core regression run.
