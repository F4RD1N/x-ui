# OpenVPN client for Xray: design contract

An OpenVPN 2.x client written from scratch in Go, run as an Xray outbound
(`"protocol": "ov"`) in the 25.3.6 fork that libv2ray builds in. It must
interoperate with stock OpenVPN 2.4–2.6 servers (and tolerate older ones),
over UDP and TCP, with tls-auth, tls-crypt, tls-crypt-v2 or no control-channel
protection, AEAD and CBC data ciphers, PRF and TLS-EKM key derivation,
certificate and/or username/password authentication, compression framing,
keepalive and renegotiation.

The outbound's name is `"ov"`. `"openvpn"`, its first name, is still
accepted as an alias (`infra/conf/xray.go`), so older configs load
unchanged and build the same configuration; new configs use `"ov"`.

## Layout

```
proxy/openvpn/                Xray glue: Handler, config.proto, gVisor stack
proxy/openvpn/ovpn/           the protocol, no Xray imports
  wire/       packet codec, TCP framing                       (done)
  ctlwrap/    plain / tls-auth / tls-crypt / tls-crypt-v2 wrapping
  reliable/   control-channel reliability layer
  handshake/  key-method 2 messages, PRF, EKM, peer info, OCC string
  compress/   compression framing, LZ4 and LZO1X decompression
  datachan/   data-channel seal/open, replay window, ping/OCC
  options/    .ovpn parser, PUSH_REPLY parser
  tlsconf/    crypto/tls client config and OpenVPN-style server checks
  client/     the session: transport, control loop, TLS, push, keys, data
  interop/    test harness: OpenVPN 2.6 servers in a network namespace
infra/conf/openvpn.go         JSON -> proto
```

Each package's exported API is in its main .go file with a doc comment that
is the specification. **Those signatures are frozen**: add exported
identifiers if you need them, but do not change or remove existing ones. If
one is genuinely wrong, implement the nearest thing and say so in your final
report.

## Ground rules

- **Clean room.** OpenVPN is GPLv2 and ooni/minivpn GPLv3; do not copy their
  code. Use the protocol as described in the package docs, RFCs and your
  knowledge of the wire format. The real OpenVPN 2.6.19 binary on this box
  (`/usr/sbin/openvpn`) is the oracle: test against it, don't read its source.
- **No new dependencies.** Standard library, `golang.org/x/crypto` (already
  in go.mod: chacha20poly1305, blowfish, pkcs12 ...) and, in the glue only,
  gVisor and `proxy/wireguard/gvisortun`. Never edit go.mod/go.sum, never run
  `go mod tidy`/`go get`.
- **Peer input never panics.** Every length read from the network is bounded
  before use. Parsers get a native Go fuzz test (`FuzzXxx`), run briefly
  (`-fuzz=FuzzXxx -fuzztime=20s`) before you finish.
- **Secrets** (keys, passwords, tokens) never go to logs.
- gofmt, doc comments on exported identifiers, errors that say what failed.
  Tests are table-driven where it fits and deterministic (inject time and
  randomness; no sleeps longer than needed).

## The build box is weak: build rules

- Run every Go command through `ovpn-gorun`, which serialises Go builds
  across agents and cages them (3 GB, 3 CPUs, low priority):
  `ovpn-gorun go test -count=1 -timeout 300s ./proxy/openvpn/ovpn/wire/`
  from `/root/android/APPS/Core/xray-25.3.6`. Waiting for the lock is normal.
- Only build or test your own packages, never `./...` at the repo root.
- `go vet` your packages before you finish.

## Interop harness contract (package interop)

`proxy/openvpn/ovpn/interop/harness.sh up|down|status` (root) brings up
network namespace `ovpntest` joined to the host by veth `ovt0` (host,
10.213.0.1/24) and `ovt1` (namespace, 10.213.0.2/24); generates a PKI and
keys with easy-rsa into `$OVPN_INTEROP_DIR` (default `/tmp/ovpn-interop`);
starts one OpenVPN 2.6 server per case inside the namespace, listening on
all of its addresses (clients use 10.213.0.2); and starts a test server inside the namespace on 0.0.0.0:8080
(HTTP: `/hello` returns `hello from ovpntest\n`, `/blob?size=N&seed=S`
returns N deterministic pseudo-random bytes, `/text?size=N` N bytes of
compressible text, `POST /echo` echoes the body) and UDP echo on
0.0.0.0:5353. A client reaches the test server at the case's server tunnel
address (x.y.z.1). `$OVPN_INTEROP_DIR/cases.json` lists every case:
`{"name", "ovpn": path of the client .ovpn, "username", "password",
"proto", "port", "tunnelServerIP", "notes"}`. Client .ovpn files have all
keys and certificates inline. `down` removes everything it made; nothing
outside the namespace changes except the veth host end.

On this build box the host's own firewall drops host-namespace IPv4 traffic
to 10.0.0.0/8, so the host cannot be the client: the harness also creates a
client namespace `ovpncli` (veth `ovc0` in ovpntest, 10.214.0.1/24, and
`ovc1`, 10.214.0.2/24), and every client dials through `interop.Dial`
(client.DialFunc's shape), which opens its sockets there. Manual runs of the
xray binary go through `ip netns exec ovpncli` for the same reason.

Cases (port: name — what it pins):

| port | name | server settings |
|------|------|-----------------|
| 1194/udp | udp-gcm-tlscrypt | tls-crypt, AES-256-GCM, subnet, IPv6 in tunnel |
| 1195/tcp | tcp-gcm-tlsauth | tls-auth (server 0 / client 1), auth SHA256 |
| 1196/udp | udp-cbc-sha1-net30 | tls-auth, data-ciphers AES-256-CBC, auth SHA1, topology net30 |
| 1197/udp | udp-chacha-userpass | no tls-auth, CHACHA20-POLY1305, username/password only (verify-client-cert none) |
| 1198/udp | udp-tlscryptv2 | tls-crypt-v2 |
| 1199/udp | udp-lz4v2 | compress lz4-v2 pushed, allow-compression yes (server compresses) |
| 1200/udp | udp-complzo | comp-lzo yes pushed, allow-compression yes (server compresses) |
| 1201/udp | udp-reneg | tls-crypt, reneg-sec 15 (renegotiates mid-transfer) |
| 1202/tcp | tcp-tls12-cbc | tls-version-max 1.2, data-ciphers AES-128-CBC, auth SHA512 |
| 1203/udp | udp-compress-stub | compress (stub, swap framing) pushed |
| 1204/udp | udp-certpass | certificate and username/password, tls-auth, AES-128-GCM |

The interop tests run only with `OVPN_INTEROP=1` and as root; otherwise they
skip.
