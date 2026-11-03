# Native OpenVPN session engine

This package implements the server direction of the OpenVPN TLS control channel
and encrypted IP data channel inside the Xray process. Production does not start
an OpenVPN executable, load a plugin, or create a kernel TUN interface.

The surrounding Xray inbound owns transport listeners, UDP association limits,
address allocation, IP source validation, the userspace IP stack, and dispatch
through Xray routing. One `Serve` invocation owns exactly one accepted TCP
connection or UDP peer association. TCP adapters must strip/add OpenVPN's
two-byte packet framing. `PacketConn.Close` must interrupt pending reads and
writes. The engine closes the transport on failure and shutdown.

`Config.Authenticate` is required. It receives the decrypted client key-method-2
message and verified TLS connection state on every TLS generation, including
renegotiation. It must enforce the selected certificate/password policy and
optional `clientProof`, respect its context deadline, and return a stable
identity plus the allocated tunnel's push options. Proof should bind the allowed
key identifier to the authenticated certificate/account and verify the current
TLS exporter's MAC. A successful proof does not replace ordinary authentication.
No data keys are installed until admission succeeds. Changing identity during a
rekey terminates the connection.

The engine supports TCP and UDP, TLS 1.2/1.3, ordinary control packets, `tls-auth`,
`tls-crypt`, and server-side `tls-crypt-v2` key unwrapping. Cipher negotiation is
restricted to the configured allowlist. The defaults are AES-256-GCM,
AES-128-GCM, and ChaCha20-Poly1305. Explicit CBC choices use the configured data
HMAC. Both the conventional key-method-2 PRF and TLS exporter derivation work,
with DATA_V1 and DATA_V2 compatibility. Compression and server-issued auth tokens
are not enabled by this package.

All queues and control message sizes are bounded. Transport writes run outside
the control loop so a blocked TCP peer cannot disable handshake/idle timers.
TLS generation count stays bounded; an old key expires after the transition
window. During a rekey, the server retains the preceding sending key until an
authenticated data packet under the new key proves that the peer received the
key-method reply; UDP control/data reordering therefore cannot create an early
unknown-key response. Further rekeys wait for that confirmation. Rekey occurs at the configured interval or before the data-channel
packet identifier budget is exhausted. Authenticated data activity controls the
idle timer; malformed unauthenticated traffic cannot keep a session alive.

## Verification

Normal package tests use ephemeral local certificates, loopback sockets, and
synthetic packet data. They exercise the current client, stock OpenVPN 2.6,
all control wrappers, cipher negotiation, PRF/exporter derivation, fresh proof on
multiple rekeys, invalid authentication, identity changes, cancellation,
concurrent calls, and bounded memory. Stock key generation is also used as an
independent oracle for `tls-crypt-v2` wrapped-key verification.

Run with the repository's Go toolchain:

```sh
go test -race ./proxy/openvpn/ovpn/server ./proxy/openvpn/ovpn/ctlwrap
```

A separate real stock-client TUN test is opt-in and refuses to run in the host
network namespace. It sends ICMP packets with 1,300-byte payloads through a temporary TUN and
the native server while keys rotate:

```sh
unshare -n env D11_OPENVPN_PRIVATE_NETNS=1 \
  go test ./proxy/openvpn/ovpn/server \
  -run '^TestStockOpenVPNTUNDataAndRekey$' -count=1
```

Only that test uses the stock OpenVPN executable and a temporary kernel TUN.
These local tests establish wire compatibility and engine behavior; panel
configuration, userspace IP routing, cross-platform builds, and full Xray
integration require their own tests in the surrounding packages.
