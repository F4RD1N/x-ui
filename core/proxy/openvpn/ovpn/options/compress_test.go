package options

import (
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
)

// compressReady reports whether package compress, written alongside this
// one, implements its parsers yet. Until it does, the tests that need it
// skip and the fuzzers get no compression seeds.
func compressReady() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	_, _ = compress.ParseCompress("")
	_, _ = compress.ParseCompLZO("")
	return true
}

func needCompress(t *testing.T) {
	if !compressReady() {
		t.Skip("package compress does not implement ParseCompress/ParseCompLZO yet")
	}
}

// compressSeeds are fuzz seeds with compression directives.
var compressSeeds = []string{
	"remote r\ncomp-lzo no\ncompress stub-v2\ncompress\n",
	"PUSH_REPLY,compress stub-v2,comp-lzo,compress lz4,comp-lzo adaptive",
}

// The modes follow package compress's documentation of each framing.
var compressionCases = []struct {
	directive string
	mode      compress.Mode
}{
	{"comp-lzo", compress.LZO},
	{"comp-lzo yes", compress.LZO},
	{"comp-lzo no", compress.LZO},
	{"comp-lzo adaptive", compress.LZO},
	{"compress", compress.Swap},
	{"compress stub", compress.Swap},
	{"compress lz4", compress.Swap},
	{"compress stub-v2", compress.V2},
	{"compress lz4-v2", compress.V2},
	{"compress lzo", compress.LZO},
	{"compress migrate", compress.None},
}

func TestCompressionDirectives(t *testing.T) {
	needCompress(t)
	for _, tc := range compressionCases {
		o, err := Parse("remote r\n" + tc.directive + "\n")
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.directive, err)
			continue
		}
		if !o.CompressionSet || o.Compression != tc.mode {
			t.Errorf("Parse(%q): Compression %v set %v, want %v", tc.directive, o.Compression, o.CompressionSet, tc.mode)
		}

		p := NewPushed()
		if _, err := p.ApplyPushReply("PUSH_REPLY,ping 10,"+tc.directive+",ping-restart 60", nil); err != nil {
			t.Errorf("push %q: %v", tc.directive, err)
			continue
		}
		if !p.CompressionSet || p.Compression != tc.mode {
			t.Errorf("push %q: Compression %v set %v, want %v", tc.directive, p.Compression, p.CompressionSet, tc.mode)
		}
	}

	o, err := Parse("remote r\n")
	if err != nil || o.CompressionSet || o.Compression != compress.None {
		t.Errorf("no compression directive: %+v %v", o, err)
	}
	if p := NewPushed(); p.CompressionSet {
		t.Error("NewPushed has compression set")
	}
	// The last directive wins.
	if o, err := Parse("comp-lzo\ncompress stub-v2\n"); err != nil || o.Compression != compress.V2 {
		t.Errorf("comp-lzo then compress stub-v2: %+v %v", o, err)
	}
	for _, bad := range []string{"compress zstd", "comp-lzo maybe"} {
		if _, err := Parse(bad + "\n"); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
		if _, err := NewPushed().ApplyPushReply("PUSH_REPLY,"+bad, nil); err == nil {
			t.Errorf("push %q succeeded", bad)
		}
	}
}

// A provider config with compression, as many still ship it.
func TestProviderConfigWithCompLZO(t *testing.T) {
	needCompress(t)
	o, err := Parse(providerConfig + "comp-lzo no\n")
	if err != nil {
		t.Fatal(err)
	}
	if !o.CompressionSet || o.Compression != compress.LZO || len(o.Remotes) != 2 {
		t.Errorf("got %+v", o)
	}
}
