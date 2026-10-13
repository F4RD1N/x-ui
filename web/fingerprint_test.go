package web

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/web/global"
)

func TestFingerprintFS(t *testing.T) {
	a := fstest.MapFS{"js/a.js": {Data: []byte("one")}, "css/b.css": {Data: []byte("two")}}
	fa := fingerprintFS(a)
	if len(fa) != 10 || fingerprintFS(a) != fa {
		t.Fatalf("not a stable short hash: %q", fa)
	}
	a["js/a.js"] = &fstest.MapFile{Data: []byte("one!")}
	if fingerprintFS(a) == fa {
		t.Fatal("a changed asset kept the fingerprint")
	}
	b := fstest.MapFS{"js/c.js": {Data: []byte("one")}, "css/b.css": {Data: []byte("two")}}
	if fingerprintFS(b) == fa {
		t.Fatal("a renamed asset kept the fingerprint")
	}
}

// Asset URLs change with the assets, not only with the version number.
func TestAssetVersionCarriesTheFingerprint(t *testing.T) {
	v := global.AssetVersion()
	if !strings.HasPrefix(v, config.GetVersion()+"-") || v == config.GetVersion() || !strings.HasSuffix(v, fingerprintFS(assetsFS)) {
		t.Fatalf("asset version %q", v)
	}
}
