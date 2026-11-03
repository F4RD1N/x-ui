# Native protocol sources and dependencies

The native client implementations were ported from this project's existing
client core. The server implementations live alongside them in `proxy/`.
Orbit also reuses the project's existing server and carrier implementation.
DNSTT framing and authority behavior use the CC0 DNSTT implementation and its
published protocol. Existing source headers and license texts are retained.

The new module dependencies include DNSTT (CC0), Noise (BSD-3-Clause), KCP and
smux (MIT), quic-go (MIT), and Google UUID (BSD-3-Clause).
The newly introduced KCP dependencies Reed-Solomon (MIT), pkg/errors
(BSD-2-Clause), and gmsm (Apache-2.0) also retain their license texts here. The Xray and panel licenses
continue to apply to their respective source trees; these additions do not
relicense existing code.

Interoperability tests use separate reference client/server executables.
Those executables are not needed by, linked into, or shipped with the production
panel/core bundles. A separately licensed reference-client test module retains
its own notices. Running those optional oracle tests requires their test tools;
using the new production protocols does not.
