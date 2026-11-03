package orbit

import (
	"testing"

	"github.com/xtls/xray-core/proxy/orbit/internal/router"
)

func TestServerTerminalMetadataPolicy(t *testing.T) {
	if !terminalMetadata(nil) || terminalMetadata([]byte{1, 2, 3}) {
		t.Fatal("empty or malformed metadata misclassified")
	}
	for _, tc := range []struct {
		path    router.ProxyPath
		allowed bool
	}{
		{router.ProxyPath{}, true},
		{router.ProxyPath{Nodes: []router.ProxyNodeInfo{{Field0: 4}}}, true},
		{router.ProxyPath{Nodes: []router.ProxyNodeInfo{{Field0: 1, TransportType: 2, Addresses: []router.NetworkAddress{{Port: 443, Kind: 1, Address: []byte{192, 0, 2, 1}}}}}}, false},
		{router.ProxyPath{Nodes: []router.ProxyNodeInfo{{Field0: 1}, {Field0: 2}}}, true},
	} {
		b, err := router.MarshalProxyPath(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if terminalMetadata(b) != tc.allowed {
			t.Fatal("terminal classification differs from the native server")
		}
	}
}
