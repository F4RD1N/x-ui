# Native OpenVPN inbound and outbound

`openvpn` and `ov` are equivalent protocol names in both directions. The inbound and outbound run in the Xray process. The production path does not start an OpenVPN executable, load an OpenVPN authentication plugin, create a host TUN device, change routes, or require root privileges. An installed stock OpenVPN executable is used only by interoperability tests.

The inbound terminates the actual OpenVPN TLS control and encrypted data channels. Each accepted outer TCP connection or UDP source association gets an independent protocol session, address lease and userspace IP stack. Decrypted TCP/UDP flows go through Xray's normal dispatcher, routes, sniffing, outbound selection, user counters and online-IP tracking. Routing and online-IP tracking retain the real outer peer source; packets must still carry the tunnel source address assigned to that session. A rejected rekey cannot change the session's identity or level. Arbitrary remote ICMP is not routed: gateway echo is answered locally, while fabricated echo replies for remote addresses are suppressed before IP fragmentation. Normal ICMP errors remain available to the stack.

## Server configuration

Inbound `listen`, `port` and `tag` use normal Xray fields. OpenVPN handles its own TCP/UDP framing and TLS; ordinary `streamSettings.security` is not required.

```json
{
  "tag": "openvpn-in",
  "listen": "0.0.0.0",
  "port": 1194,
  "protocol": "openvpn",
  "settings": {
    "network": "udp",
    "certificates": {
      "ca": "CLIENT-CA-PEM",
      "cert": "SERVER-CERTIFICATE-PEM",
      "key": "SERVER-PRIVATE-KEY-PEM"
    },
    "crypto": {
      "dataCiphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
      "authHash": "SHA256"
    },
    "tunnel": {
      "ipv4": "10.88.0.0/24",
      "ipv6": "fd88::/64",
      "dns": ["1.1.1.1"],
      "mtu": 1400
    },
    "clients": [{"email": "client-1", "commonName": "client-1", "level": 0}],
    "limits": {
      "maxSessions": 128,
      "maxSessionsPerIP": 16,
      "maxFlowsPerSession": 256,
      "handshakeSeconds": 15,
      "idleSeconds": 120
    },
    "renegotiationSeconds": 3600
  }
}
```

PEM placeholders are explanatory and not valid credentials. Server private key and client private key are different. Clients must supply certificates valid under `certificates.ca`; certificate common name maps to one configured client. Optional `username` and `password` on a client add account authentication to certificate authentication. A blank `clients` list starts a fail-closed listener and does not create a default user. Removing a user through Xray's user API revokes its active sessions. Certificate identity, email and optional proof key IDs must be unique.

IPv4 subnet defaults to `10.88.0.0/24`; IPv6 is optional. The first host is the tunnel gateway and later hosts are leased to sessions. Both pools must fit the configured session limit. MTU is 1280–8000, default 1400. An explicit destination's loopback address is permitted by the private packet stack and remains subject to normal Xray routing; use routing rules for destination restrictions.

TLS-auth, TLS-crypt and TLS-crypt-v2 are optional and mutually exclusive:

- `certificates.tlsAuth`: standard static key PEM. Omitted `keyDirection` means bidirectional, like stock OpenVPN. Explicit server direction `0` requires client direction `1`, and vice versa.
- `certificates.tlsCrypt`: standard static key PEM shared with clients. No direction field.
- `certificates.tlsCryptV2`: the server wrapping-key PEM. Exported clients need separately issued client-key PEM, never the server key.

Native Go generation helpers in `ovpn/ctlwrap` provide `GenerateTLSCryptV2ServerKey`, `(*TLSCryptV2ServerKey).MarshalPEM`, and `IssueTLSCryptV2ClientKey`. No external executable is needed to issue these keys.

The default cipher list uses AEAD. AES-CBC and BF-CBC are supported only when explicitly selected; aliases are normalized before validation. TLS 1.2 or newer is required. The native server supports TUN IP mode, key method 2, PRF and TLS-exporter data keys, data packet v1/v2, control retransmission, replay checks and session rekeys. Server-side legacy compression framing is rejected explicitly. TAP, static-key non-TLS mode and seamless UDP source rebinding are not server features. A UDP client whose source tuple changes reconnects. The existing outbound retains its broader stock-server profile parsing and compression compatibility.

## Optional client proof

For a protected client add:

```json
"clientProof": {
  "keyId": "client-1",
  "key": "64-HEXADECIMAL-CHARACTERS-FROM-32-RANDOM-BYTES"
}
```

This object belongs inside that client's server record and inside the client's outbound settings. A configured per-client proof key is required for that client. Setting server settings `"clientProof": {"required": true}` requires every configured client to have one. Omitting proof preserves normal stock-client authentication. Invalid/missing proof never falls back to unprotected authentication.

The existing wire contract is unchanged: encrypted peer info `UV_CORE_PROOF` contains a canonical HMAC value bound to the current TLS exporter, key ID and authenticated certificate identity. Every renegotiated TLS generation is checked. A copied proof cannot authenticate a different TLS session. This proves possession of the configured secret, not that a client binary is unmodified.

Passwords, proof keys, private keys and raw settings are excluded from diagnostic formatting. Explicit JSON/protobuf serialization intentionally contains configuration secrets: protect configuration files and backup archives accordingly. Backups must include key/certificate material; external filename references alone are not portable.

## Client outbound compatibility

The existing client accepts `ovpn` as text or lines, `ovpnBase64`, or the structured `server`/`auth`/`crypto`/`certificates`/`advanced` form. These forms are mutually exclusive. The structured client fields are:

```json
{
  "protocol": "openvpn",
  "settings": {
    "server": {"address": "vpn.example.invalid", "port": 1194, "network": "udp"},
    "crypto": {"cipher": "AES-256-GCM", "dataCiphers": ["AES-256-GCM"], "authHash": "SHA256"},
    "certificates": {"ca": "SERVER-CA-PEM", "cert": "CLIENT-CERTIFICATE-PEM", "key": "CLIENT-PRIVATE-KEY-PEM"},
    "advanced": {"dev": "tun", "nobind": true, "remoteCertTls": "server", "mtu": 1400}
  }
}
```

Existing `username`, `password`, `mtu`, `domainStrategy`, structured `auth`, and `clientProof` fields retain their meanings. Proof accepts exactly one `key` or private `keyFile`. TLS-crypt-v2 clients use the issued client key under `certificates.tlsCryptV2`.

## Isolation and verification

Protocol additions live under this package and `infra/conf/openvpn*.go`. The userspace stack and ICMP helpers are private copies so existing WireGuard and ICMP implementations remain unchanged. Existing notices remain with copied code. The server owns and closes its packet filter's maintenance clock separately from normal stack timers; closing a session stops and drains that maintenance work. The only shared lifecycle integration is additive mux-context metadata: it lets OpenVPN distinguish a mux End from a TCP half-close, without altering mux framing or existing protocol behavior.

Tests exercise stock OpenVPN against the native engine before custom interoperability, real stock TUN traffic, TCP/UDP wrappers, native-issued TLS-crypt-v2 keys accepted by stock OpenVPN, cipher/PRF/exporter variants, optional proof and rejection paths, proof across rekeys, malformed input, replay, resource limits, concurrent sessions, cancellation and panic containment. Full Xray tests exercise actual routed TCP/UDP payloads, live destination rejection, user byte/online-IP accounting, client revocation, IPv6 and coexistence with the existing freedom outbound. Configuration tests build the complete Xray JSON through both protocol aliases and retain proof fields.

The test commands are ordinary Go tests; this project's build host serializes them using its shared build lock. Stock-oracle tests skip explicitly if their prerequisites are absent. Controlled real-network-namespace/TUN tests require an explicit opt-in; they are not production dependencies. Reports should distinguish executed, skipped and failed tests and preserve the exact logs.
