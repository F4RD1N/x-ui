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
validated update. Unrelated users and server settings are retained. Explicit
AnyTLS CA bundles are filtered to public certificate blocks before export, so
an accidentally pasted private PEM block cannot reach subscribers.

Longer OpenVPN sessions exposed a timer publication race in the new server
handler's private network stack. The filter timer now waits until initialization
is published, and shutdown releases waiting callbacks without running them.
This is confined to the bundled OpenVPN server implementation; other protocol
handlers and the separate custom client core are unchanged.

## Verification

Final verification results and release artifacts are recorded after the
generated-profile integration and browser checks complete. Earlier protocol
compatibility limits remain documented in [DIALECT11.md](DIALECT11.md) and
[DIALECT11-VERIFICATION.md](DIALECT11-VERIFICATION.md).
