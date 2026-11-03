package all

// Native protocol handlers are linked into the same Xray executable. Merely
// registering a handler starts no listener, goroutine, or external process.
import (
	_ "github.com/xtls/xray-core/proxy/anytls"
	_ "github.com/xtls/xray-core/proxy/dnstt"
	_ "github.com/xtls/xray-core/proxy/mieru"
	_ "github.com/xtls/xray-core/proxy/openvpn"
	_ "github.com/xtls/xray-core/proxy/orbit"
	_ "github.com/xtls/xray-core/proxy/shadowtls"
)
