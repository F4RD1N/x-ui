# Native DNS tunnel

The inbound and outbound run in the Xray process. They do not start an external
server, plugin, shell command or loopback proxy. A DNS authority carries KCP,
Noise NK and smux version 2. Each stream then authenticates with the existing
VLESS or SOCKS handler and uses the ordinary Xray dispatcher, routing and user
policy.

## Server

```json
{
  "tag": "dns-tunnel",
  "listen": "0.0.0.0",
  "port": 53,
  "protocol": "dnstt",
  "settings": {
    "domain": "tunnel.example.net",
    "privateKey": "<64 hexadecimal digits>",
    "inner": {"protocol": "vless"},
    "clients": [
      {"id": "<nonzero UUID>", "email": "user@example.net", "level": 0}
    ],
    "mtu": 1232,
    "handshakeTimeout": 30,
    "maxSessions": 256,
    "maxStreams": 128
  }
}
```

`domain`, `privateKey` and authenticated clients must agree with the exported
client configuration. An empty client list is permitted to disable access.
The private key is a randomly generated 32-byte X25519 key. Derive its public
key with `crypto/ecdh.X25519().NewPrivateKey(bytes).PublicKey().Bytes()` and
encode both as hexadecimal. Retain the same key when editing or restoring an
inbound.

`mtu` is the maximum authoritative DNS UDP response size, from 512 to 4096.
1232 avoids common IPv6 fragmentation problems. The Noise handshake timeout
is 1–300 seconds. Inner proxy authentication also observes the normal Xray
policy handshake timeout. `maxSessions` bounds authenticated tunnel identities, up to 4096.
A separate budget holds at most 64 pending identities; it evicts the oldest
unauthenticated identity independently of poll traffic. Pending identities are
promoted only after successful inner authentication, and expire after the
configured Noise handshake timeout plus five seconds. Polls cannot pin the
authenticated capacity. `maxStreams` bounds simultaneous smux streams
per session, up to 1024. A separate shared budget limits unauthenticated
stream handlers to at most 256 without reducing established authenticated
stream capacity. Defaults are shown above. Logical idle state expires
after two minutes; idle recursive-source associations expire after three seconds.
These source associations are separate from authenticated tunnel sessions.

VLESS is the default inner protocol and supports TCP and fixed-destination UDP.
It uses ordinary version-zero VLESS with encryption `none` inside the already
encrypted tunnel. Vision, reverse mode and extra VLESS dialects are not used.
The native handler supports live VLESS user additions and removals.

For SOCKS5, set `inner.protocol` to `socks` and use clients with `username`,
`password` and optional `level`. Both credentials must contain 1–255 bytes,
and the policy level must be the same for all SOCKS users. SOCKS inner supports
TCP only and requires reload for user changes. HTTP fallback, SOCKS4 and
anonymous SOCKS5 are explicitly rejected within this tunnel.

The inbound alias `protocol: "dns"` uses the same native server settings.

## Client

```json
{
  "tag": "dns-tunnel",
  "protocol": "dns",
  "settings": {
    "tunnel": {
      "domain": "tunnel.example.net",
      "publicKey": "<64 hexadecimal digits>",
      "resolvers": [{"transport": "udp", "address": "1.1.1.1:53"}],
      "inner": {"protocol": "vless", "uuid": "<the same UUID>"}
    }
  }
}
```

Ordinary `dns` settings without `tunnel` retain stock DNS behavior. The outbound alias
`protocol: "dnstt"` accepts the tunnel object directly as `settings`. Explicit
tunnel settings reject nulls, unknown fields and mixed ordinary DNS settings.

Resolvers can use `udp`, `dot` or `doh`. DoT and DoH are the client-to-recursive
resolver leg; the authoritative server remains UDP. A resolver hostname needs
numeric `bootstrap` to avoid recursive DNS dependencies. Resolver TLS supports
`serverName`, `caPem`, and the existing empty/chrome/firefox/safari fingerprints.
Certificate verification remains enabled. Do not place resolver TLS settings
on the authoritative inbound's outer stream.

The client query timeout defaults to five seconds, exceeding the authority's
maximum one-second long poll. An explicitly shorter timeout reduces tolerance
for resolver latency and scheduling delays. Noise authentication pins the
server public key; it does not replace the inner client credentials.

## Deployment and backup

Public recursive-resolver use requires an A/AAAA record for the authoritative
server and an NS delegation for the tunnel suffix. The server must receive
authoritative UDP traffic on port 53, directly or through a configured redirect.
Installing the native core does not create public DNS delegation automatically.
Direct high-port loopback tests exercise the protocol without public DNS.

Keep private key, domain, inner users and limits in persisted inbound settings.
Backups must preserve them exactly. Export the corresponding public key and
the selected resolver settings; never regenerate authentication keys during
restore. No private material file or external server executable is required.

## Verification

The package tests exercise UDP/DoT/DoH, large TCP transfers, simultaneous
streams, inner UDP, routing, authenticated SOCKS, incorrect credentials,
malformed DNS, queue/stream/session bounds, query loss, shutdown and live users.
The config tests also launch real core instances to exercise plain stock DNS
and both tunnel JSON forms.

```sh
GOMAXPROCS=2 go test -race -p 2 ./proxy/dnstt/...
GOMAXPROCS=2 go test -race -p 2 ./infra/conf -run TestDNSTTConfig
```

Set `XRAY_DNSTT_REFERENCE_CLIENT` to an independently built compatible client
binary to enable its additional end-to-end test against the native server.
Without that variable, the reference-binary test is explicitly skipped.
Test fixtures use loopback sockets, generated local certificates and synthetic
credentials; they never perform Internet DNS recursion.

The DNS wire routines retain their attribution to the CC0 DNSTT server source.
See `../../licenses/dnstt-CC0-1.0.txt` and the licenses of the imported Noise,
KCP and smux dependencies.
