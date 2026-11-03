# Complete client JSON export

Dialect 11.7 adds **Copy full JSON config** to each native protocol client's
actions on the Inbounds page. On a small screen, open the client's action menu.
The export is independent of the public subscription service.

Supported protocols are Orbit, DNS over V2Ray (DNSTT), OpenVPN, AnyTLS,
ShadowTLS and Mieru. These configurations require a compatible custom client
core; adding this button does not add these protocols to stock Xray.

## Exported configuration

Each export is one standalone JSON object for the selected inbound and client.
It includes a SOCKS listener on `127.0.0.1:10808`, UDP support, sniffing,
the selected protocol's complete outbound graph, direct/block outbounds and
routing. ShadowTLS retains its inner outbound and carrier chain. DNSTT uses
the client core's `dns` outbound with tunnel settings.

The exporter reuses the native subscription serializer. Saved custom
authentication, certificate trust and client material are preserved. Exporting
does not generate new keys, rotate passwords or change saved settings. It does
not include other clients' credentials, CA issuer private keys or server private
keys. An OpenVPN client private key is included because the client needs it.

Required deployment data must already be configured. Incomplete, disabled,
expired or exhausted accounts are rejected rather than exported as working
profiles. The exported server endpoint uses saved protocol metadata/listener
information, with the panel request hostname as the wildcard-listener fallback.
A proxy forwarding the panel should preserve the public Host header.

## Clipboard and download

The copy action supports HTTPS clipboard APIs and an HTTP-compatible fallback.
If the browser does not permit copying, the panel opens the JSON for manual
copying or downloading. A success notification is shown only after copying
succeeds.

## Panel API

Authenticated requests can use:

```http
POST <panel-base>/panel/api/inbounds/<inbound-id>/clientConfig
Content-Type: application/json

{"email":"selected-client"}
```

The normal panel response envelope contains `obj.config` (a complete JSON
object) and `obj.filename`. Requests must select an inbound owned by the logged
in user and one unambiguous client email. Responses are marked `Cache-Control:
no-store`. The route is read-only and does not depend on subscription IDs.

## Implementation boundaries

Native outbound serialization is shared between subscriptions and panel
exports. The panel-specific wrapper and client action are separate from legacy
protocol exports. This release changes no protocol implementation or bundled
core behavior.

The release verification report records the tests actually completed; no test
matrix can establish that every remote server, browser or network will work.
