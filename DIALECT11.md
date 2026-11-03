# Dialect11 native protocol integration

This release extends the released dialect10 panel/core, including its existing
VLESS client-version controls. It does not include the separate multi-instance
branch. The bundled server core keeps dialect10's Xray 26.3.27 base and adds
compatibility with the project's custom 25.3.6 client protocols.

Orbit, DNSTT, OpenVPN, AnyTLS, ShadowTLS, and Mieru execute inside the Go Xray
process as native handlers. Production use requires no protocol daemon,
adapter executable, additional plugin, or separate shared library. Existing
Xray routing remains responsible for each authenticated destination.

## Panel configuration

Select the protocol in the inbound editor. Starting with `.11.4`, a new native
selection generates fresh required credentials and certificates automatically;
see [DIALECT11-DEFAULTS.md](DIALECT11-DEFAULTS.md) for the defaults and lifecycle.
The native form preserves advanced JSON fields when moving
between form and JSON editing. Server outbound settings expose the same native
protocols. Native transports are configured inside protocol settings: adding an
unrelated outer WebSocket/TLS layer is rejected. AnyTLS is the exception: its
inbound uses normal Xray TCP plus `streamSettings.security: "tls"`, while its
outbound owns its TLS connection internally.

| Protocol | Inbound identity and material | Client outbound |
| --- | --- | --- |
| Orbit | Per-user connection key; pinned leaf certificate/key, or TCP Reality material | `protocol: "orbit"`; TCP, WS, WSS, or compatible QUIC |
| DNS tunnel | Tunnel name, hexadecimal Noise private key, authenticated inner VLESS or SOCKS accounts | `protocol: "dns"`, `settings.tunnel`; `dnstt` remains an alias |
| OpenVPN | CA/server certificate/private key, certificate CN accounts, optional password/proof and control wrapper | `protocol: "openvpn"` (`ov` alias); TCP or UDP |
| AnyTLS | TLS certificate/key plus password accounts | `protocol: "anytls"`, optional UUID authentication compatibility |
| ShadowTLS | Camouflage TLS endpoint, carrier authentication, explicit authenticated inner proxy | Inner outbound chained through `protocol: "shadowtls"` |
| Mieru | Username/password accounts; TCP or UDP underlay | `protocol: "mieru"`; both underlays carry TCP and UDP destinations |

Ordinary `protocol: "dns"` without `settings.tunnel` remains the stock DNS
outbound. Direct DNS tunnels connect to the server's UDP address and port.
Using recursive resolvers instead requires real authoritative DNS delegation
and a route from the selected resolver to the server. The panel cannot create
registrar delegation or make a blocked resolver reachable. Inner VLESS carries TCP and
UDP; inner SOCKS supports authenticated TCP only.

OpenVPN authenticates client certificates against the CA and maps the
certificate common name to the configured account. Per-client PEM certificate
and private key fields in the panel are **client export material**. Generated
profiles issue distinct matching client certificates and keys automatically.
Manually imported pairs must also match; server keys are not client keys.
Optional username/password and client proof add checks to certificate
authentication. `tlsAuth`, `tlsCrypt`, and `tlsCryptV2` are mutually exclusive.
An absent TLS-auth direction remains bidirectional; explicit server direction
0 exports client direction 1, and explicit 1 exports 0. TLS-crypt-v2 client keys
must be issued under the server wrapping key, not copied from it.
The native OpenVPN server routes TCP and UDP through Xray; it does not provide
arbitrary remote ICMP forwarding. Production uses a userspace IP stack and
does not require a host TUN device.

The panel's authenticated `POST /panel/api/server/native/credentials` helper
generates complete native inbound profiles, DNS tunnel key pairs,
certificate/Reality-bound Orbit account keys, OpenVPN client certificates,
proof secrets, and TLS-crypt-v2 server/client keys. It returns generated
material without saving it automatically. Responses use `Cache-Control:
no-store`; request values and secrets are not included in error messages.

## Optional compatibility fields

All compatibility options default off. Enable them only for matching clients.

| Field | Scope | Meaning |
| --- | --- | --- |
| `rawUuidAuth` | VMess inbound account / outbound user | Existing raw-UUID authentication format |
| `clientProof` | OpenVPN account and outbound; server `required` policy | Certificate/account-bound TLS exporter HMAC proof, checked again on rekey |
| `uuidHashMiddle` | AnyTLS account and outbound | UUID-bearing authentication digest compatibility |
| `requireUuidSessionId` / `uuidSessionId` | ShadowTLS v3 server account / client | Require/send the compatible UUID session-ID form |
| `uuidMetadataTrailer` | Mieru account and outbound | Verify/send UUID metadata trailers on client-to-server records |
| `uuidHashPrefix` | Trojan account and outbound | Compatible binary UUID prefix in the authentication field |
| `uuidIdentityKeys` | SS2022 client identities and outbound server | Import UUID identities as ordinary 16/32-byte SS2022 keys |

The SS2022 option does not introduce a new cipher. The server PSK stays normal
base64. A UUID identity becomes base64 of its 16 raw bytes for AES-128, or those
bytes repeated twice for the 32-byte methods. Existing base64 identities remain
unchanged. The option requires an exact supported `2022-blake3-*` method.

These compatibility options are not automatically stronger authentication or
encryption. In particular, VMess raw UUID mode exposes the UUID in its AuthID
and uses it for its compatible header key; use a protected outer transport
when credential confidentiality is required.

## Client exports and user lifecycle

Use the existing **JSON subscription endpoint** for the native protocols.
Ordinary URI and Clash formats cannot represent all required settings; the
panel does not silently substitute a direct connection. Custom VMess/Trojan
options are retained in supported exports, and unsupported Clash combinations
explicitly require JSON. SS2022 URI/Clash exports use canonical key material.

Native JSON export selects one client's credentials. ShadowTLS exports both
the inner outbound and its carrier chain, binding inner users by the selected
client's email or explicit SOCKS username. OpenVPN export checks the client
certificate/key pair and CN and never substitutes server private material.
Server-only private keys, CA private keys, other users, and panel metadata do
not belong in client exports.

Exports contain actual endpoints and account IDs. The current customized
25.3.6 client's separate, default-on endpoint-mapping feature must be disabled
for these raw configs, using its existing `xray.endpoint.mapping=off` environment
setting or the app wrapper's `SetObfuscationEnabled(false)`. Otherwise that
feature deliberately rewrites correct VLESS endpoints, including a ShadowTLS
inner VLESS outbound. No client source change is needed.

User changes use native typed account operations where supported. Protocols
whose inner accounts cannot be safely updated live explicitly request a core
reload. An unsupported user operation never reports fictitious success.
Disabled/expired clients are filtered before core generation, and listeners
without active native accounts cannot become anonymous proxies.

## Portable backup and restore

Panel and Telegram backups use a versioned ZIP containing a consistent SQLite
snapshot, a manifest with integrity hashes, and referenced certificate/key
assets. Inline native settings, optional flags, client export material, outbound
templates, and routing remain in SQLite. Legacy SQLite backups remain importable.

Restore stages and validates the database schema, assets, and generated core
configuration before stopping the current runtime. Assets are installed only
under a newly created managed directory and references are rewritten; archive
paths never choose filesystem destinations. Files receive private permissions.
Duplicate members, traversal, links, missing assets, invalid hashes, excessive
sizes, and active SQLite schema objects are rejected. Current limits are 128
MiB for the database, 4 MiB per referenced asset, 256 assets, and 192 MiB total.

The previous database remains available until the new runtime starts
successfully. A failed migration, replacement, or startup triggers rollback;
manually stopped runtime state is preserved. External DNS delegation, domain
ownership, public certificate issuance, and remote camouflage availability are
deployment prerequisites rather than restorable local files. Backups contain
private keys and must be stored privately.

## Transport compatibility limits

Orbit TCP is the default. The existing compatible QUIC Initial trailer places
recoverable account credentials outside QUIC packet protection. This is an
inherited wire limitation; pinned server TLS does not remove it. TCP, WS, WSS,
and TCP Reality protect the native identity inside the encrypted carrier. A
versioned client/server change is needed to repair QUIC credential
confidentiality. Compatible QUIC also expects a stable UDP source tuple.

Mieru defaults to the TCP underlay, which can still carry UDP application
traffic. The compatible Mieru UDP format reuses its AEAD key/nonce for metadata
and payload in a datagram. This behavior is also present in the independent
reference implementation; changing it on one side breaks interoperability.

ShadowTLS authenticates and disguises a carrier; it does not encrypt the
post-handshake payload. Plain inner SOCKS/VLESS likewise do not encrypt that
payload beyond any application TLS. Use the supported encrypted inner
Shadowsocks option when that protection is needed. WSS outer trust and Orbit's
inner certificate pin are separate: WSS clients still need a trusted outer
certificate. No export silently disables certificate verification.

## Isolation and verification

The handlers and protocol tests are isolated under `core/proxy/`. Parser,
registration, panel serialization, account API, export, and restore integration
are additive. Existing VMess/Trojan account changes implement only the requested
optional modes. One internal mux context marker supports the new OpenVPN
half-close lifecycle without changing other protocol wire behavior.
The encrypted ShadowTLS/SS2022 integration also exposed an existing shared
packet-buffer close/read race. The packet bridge now synchronizes buffer
ownership and disposes of late read results after cancellation. This changes
shared lifecycle handling, not protocol framing or authentication; its existing
consumers receive regression coverage alongside the new protocols.

Verification uses generated local accounts, actual routed traffic, independent
reference clients/servers, cancellation and malformed-input tests, race tests,
browser serialization checks, and an isolated real panel/backup/restore
exercise. Reference programs are test tools only. The release verification
report records actual runs, failures resolved, skipped checks, architectures,
and remaining limits; it does not claim that finite testing covers every
possible deployment or future defect.

Detailed core schemas are documented beside the protocol implementations.
Original and dependency license notices remain in the source and release
bundles.

See [DIALECT11-VERIFICATION.md](DIALECT11-VERIFICATION.md) for exact release
results and remaining findings, including an independently reproduced,
inherited race in the stock SS2022 UDP dependency. Its handlers and dependency
version remain unchanged by this release.
