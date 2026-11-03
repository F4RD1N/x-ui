# Native Orbit inbound and outbound

Orbit is compiled into this Xray binary. The inbound uses the existing Xray TCP or UDP receiver and sends every authenticated logical flow through Xray's dispatcher. It requires no separately installed process or plugin. Other protocols and transport defaults are unchanged.

## Inbound settings

The usual inbound `listen`, `port` and `tag` fields select the listener. Set `protocol` to `orbit`. The carrier is selected inside `settings.transport`, not by adding an outer generic Xray transport. Generic TCP with no external security wrapper is the receiver configuration; `transport: quic` makes the protocol use the UDP receiver automatically.

```json
{
  "protocol": "orbit",
  "listen": "0.0.0.0",
  "port": 8443,
  "tag": "orbit-in",
  "settings": {
    "transport": "tcp",
    "clients": [
      {
        "email": "user@example.invalid",
        "level": 0,
        "key": "GENERATED_VCK1_CONNECTION_KEY",
        "expiresAt": 0
      }
    ],
    "tls": {
      "certificate": ["LEAF_CERTIFICATE_PEM"],
      "key": ["PRIVATE_KEY_PEM"]
    },
    "handshakeTimeout": 15,
    "maxSessions": 1000,
    "maxFlows": 128,
    "udpIdleTimeout": 60
  }
}
```

The placeholders above must be replaced. The certificate fields are arrays of PEM lines or arrays containing complete PEM strings. The first certificate must be a server leaf, not a CA certificate. Its private key must match. A normal account key must contain that leaf's SPKI pin.

The native `UserManager` supports adding, listing and removing accounts. Removal cancels that account's active sessions. `expiresAt` is Unix time in seconds; zero means no protocol-level expiry. It is separate from any panel database timestamp format. Account identity and level come from server settings, not a client-claimed level. Empty account lists deny new authentication until accounts are added.

| Carrier | Additional settings |
| --- | --- |
| `tcp` | `tls` for the pinned inner TLS carrier |
| `quic` | `tls`; listener uses UDP on the configured port |
| `ws` | `tls`, `host`, optional `path` defaulting to `/core` |
| `wss` | Same as WS, plus `outerTls` with its own `certificate` and `key` arrays |
| TCP Reality | `security: "reality"` and `reality: {privateKey, serverNames, shortIds, dest}`; omit `tls` |

WSS outer trust and inner certificate pin are independent. Clients need a normally trusted outer WSS certificate, and the inner leaf must match the connection key. Reality `dest` is the TCP cover address in `host:port` form. Its server names are normalized and validated before use. Reality cover probing happens lazily under a bounded deadline on the first connection; loading or testing JSON opens no socket.

Limits: handshake timeout 1–90 seconds, sessions 1–10000, streams/UDP mappings per authenticated channel 1–4096, UDP idle timeout 1–3600 seconds. Zero chooses the defaults shown above. At most 10000 native accounts are accepted. UDP envelopes support IPv4 and payloads through 1470 bytes. Xray's ordinary link pipeline does not preserve empty UDP datagrams. The compatible QUIC implementation admits one active session per UDP source tuple; it does not promise QUIC connection migration.

## Outbound compatibility

The current client's outbound JSON remains supported unchanged. Use either `settings.link` with an `orbit://` link (`core://` alias accepted) or the separate fields `address`, `port`, `key`, `transport`, and any applicable WS/Reality settings. Do not combine link credentials/transport fields with separate overrides. Carriers are `tcp`, `quic`, `ws` and `wss`; `auto` is not supported. TCP/QUIC server addresses must be numeric IPs. WS/WSS may use DNS names. Reality is TCP-only.

`handshakeTimeout` and `resolver` retain their current client meanings. The resolver is a numeric IPv4 DNS endpoint used through the tunnel for domain-addressed UDP. No socket or background session starts until an outbound is used.

## Authentication and key generation

A `vck1_` connection key is a bearer secret. It is 91 characters: prefix plus canonical unpadded base64url of a random 32-byte account seed and a 32-byte public-key pin. Never log the key or the derived wire credentials.

`orbit.GenerateConnectionKey(certificatePEM)` generates a fresh account bound to a public leaf certificate. The helper needs no server private key. For a Reality listener, `orbit.GenerateRealityConnectionKey(publicKey)` uses the X25519 public key hash for the required pin-shaped field. Reality itself authenticates that carrier; the ordinary TLS pin field is unused in Reality mode. Neither helper reuses a previous account seed.

The server checks the derived token in constant time, verifies device identity and account expiry, and does not dispatch application traffic until authentication succeeds. Relay/transit metadata is refused according to the current terminal-path rules. Reach/application control responses remain wire compatible.

### Existing QUIC credential limitation

The current QUIC wire format places its native identity envelope in a custom Initial trailer outside QUIC packet protection. The envelope uses an embedded fixed encoding key available in the protocol source. It therefore does **not** keep bearer credentials confidential from a passive observer. The server's pinned TLS authentication does not repair this pre-handshake disclosure. Compatibility with the existing client preserves this format; fixing it requires a versioned change on both ends. The TCP, WS, WSS and TCP Reality modes send the native identity inside their authenticated encrypted carrier. Do not describe the compatible QUIC mode as providing confidential client credentials.

## Routing, lifecycle and backup

Each logical flow receives private inbound, outbound and sniffing metadata. This prevents concurrent multiplexed flows from sharing mutable routing destinations or sniffed names. TCP uses normal dispatch links; UDP preserves packet destinations and shares mappings between physical sessions of the same authenticated user/channel. Xray user-level policy, user traffic counters, inbound tags and routing rules remain applicable.

All listener activity belongs to `Process` and the native server lifecycle. Session/flow cancellation interrupts blocked reads and writes. `Close` cancels active sessions and waits for native work to finish. QUIC receives packets from the existing UDP worker through a bounded packet adapter; no hidden extra UDP socket is bound.

Backups must preserve the complete client key, the matching TLS leaf/private key, WSS outer material when used, Reality private key/names/short IDs, outbound settings and routing rules. Regenerating a key or certificate private key during restore invalidates existing normal client pins. Keep backup material private. Panel-only bookkeeping fields must be stripped from the strict core client schema, and panel milliseconds must be converted to seconds when setting `expiresAt`.

## Verification scope

Local tests exercise the current client carrier code against the native inbound, real Xray receiver/dispatcher routing, authentication rejection, account changes, concurrent flow metadata, UDP backpressure shutdown and certificate trust. Transport tests include production QUIC Initial admission and shutdown with virtual packet connections, WebSocket origin checks and Reality proof handling. Tests use generated local credentials and loopback fixtures; they do not contact VPN providers. Exact executed commands and results are recorded in the release verification report rather than inferred from this source document.
