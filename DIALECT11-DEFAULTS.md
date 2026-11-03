# Native profile setup and panel updates — dialect11.5

This release leaves deployment information for the operator to enter. It still
generates credentials and cryptographic material, but does not invent domain
ownership, public endpoints, external DNS resolvers or third-party TLS targets.
It also fixes repeated panel updates failing with an already-loaded systemd
service and adds progress and outcome reporting.

## New inbound forms

| Protocol | Generated material | Operator-supplied deployment information |
| --- | --- | --- |
| Orbit | Inner certificate, private key and bound client connection key; optional Reality keys and short IDs | Numeric public server address; WS/WSS Host and inner peer when needed; Reality destination and server names; trusted WSS outer certificate |
| DNS tunnel | X25519 key pair and inner VLESS or SOCKS credentials | Actual tunnel domain; optional recursive resolver choices |
| OpenVPN | Private CA, separate server/client certificates and keys, TLS-crypt-v2 keys; optional client proof | Optional DNS servers and external server-name override |
| AnyTLS | TLS certificate and private key, client password and public CA trust | TLS server DNS name or IP address |
| ShadowTLS | Outer password and matching encrypted inner credentials | Reachable TLS handshake target and any needed TLS identity |
| Mieru | Username and password | Any deployment-specific endpoint or optional values |

For AnyTLS and Orbit, enter the identity first, then select **Generate
credentials**. Typing never issues a certificate for an incomplete identity.
Other protocols generate their cryptographic material immediately, leaving
required deployment fields blank. Save remains blocked until required fields
are valid. A credentials-ready notice does not mean missing deployment fields
have been completed.

The panel does not take these values from the browser address, request Host or
listen address, and does not resolve the panel hostname to guess a public VPN
endpoint. Names such as `.tunnel.invalid` and `vpn.internal`, and default
third-party cover sites, are no longer generated.

Local protocol defaults remain: conventional ports, cipher lists, MTU, limits,
the `/core` WebSocket path and OpenVPN's private `10.88.0.0/24` subnet. These are
configurable local settings, not claims about external infrastructure.
New outbound forms already left remote endpoints, identities and resolvers
blank; their behavior is retained.

## Certificates and DNS

Certificate validation stays enabled. AnyTLS certificates use the explicitly
entered DNS name or IP. Orbit certificates include the explicitly entered
numeric endpoint. OpenVPN may generate a server certificate with an internal
common name and no DNS SAN because its standard server-certificate validation
does not require a public hostname. An operator-supplied identity can still be
used when needed.

Generated leaf certificates last one year, bounded by their issuer's lifetime;
generated CAs last ten years. Operators must renew them before expiration.
Automatic key generation does not provision DNS delegation, firewall access,
publicly trusted certificates or third-party infrastructure.

New OpenVPN profiles explicitly contain `tunnel.dns: []`. A narrow serialization
fix keeps this empty list through panel projection, core configuration building
and runtime parsing. Previously, `omitempty` dropped it, causing runtime parsing
to restore an external resolver. An omitted or null DNS list in legacy
configurations retains its existing behavior; explicitly supplied resolvers are
preserved.

Subscription export compatibility is unchanged. When no DNSTT recursive
resolvers are specified, the export can still derive the direct DNS listener
from the configured endpoint and port. That does not create a public DNS
delegation or automatically fill the form. Existing endpoint and SNI export
fallbacks are retained for saved configurations.

## Preservation and private material

Opening existing inbounds, importing, cloning and restoring backups do not
regenerate their credentials or erase their deployment values. Async generation
preserves user edits, discards stale results and allows retry after an identity
change. Generated CA trust is merged alongside explicit identities rather than
being lost when the identity creates a new metadata object.

OpenVPN stores its CA signing key in private panel metadata for issuing later
clients. This metadata is removed from server runtime configuration and is not
sent to subscribers. Private backups retain it so issuance continues after a
restore. Imported deployments without their issuer key are not silently
replaced by a different CA.

## Update recovery

The former updater always used `x-ui-update.service`. A lingering transient
unit could make systemd reject another attempt before any download began. The
new updater uses a unique unit for each attempt and a shared process lock to
prevent concurrent installers. It runs independently of the panel service, so
restarting the panel does not kill the updater halfway through installation.

The installer uses the same lock for command-line updates. Downloads have
bounded connection, transfer and retry times. Temporary installer files are
private, and update output remains in the panel's `update.log`. The authenticated
status response reports progress and outcome without exposing raw log content.
The UI follows the accepted job, handles the panel restart, and reports failure
or a lost connection instead of leaving an indefinite busy indicator. It never
automatically submits another update request.

Existing databases, inbounds, credentials and panel settings remain in place.
An already-running legacy updater is not stopped or replaced by another attempt.

## Verification

Verification results and final artifact hashes are recorded in the release
report. Tests use controlled local endpoints, isolated databases and disposable
network namespaces. The updater tests use fake installers and private test
units; they do not download or deploy a release on the live panel.

The only production core change in this patch is OpenVPN's explicit-empty-DNS
serialization. The other protocol implementations and separate client-core
source are unchanged. Earlier dialect11.4 verification remains historical
rather than being relabeled as a test of this release:
https://github.com/F4RD1N/x-ui/blob/v2.9.0-dialect.11.4/DIALECT11-DEFAULTS.md
