package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/router"
)

// VPN-Core 0.12 transport/http_test.go: TestHTTPParametersAndBounds and
// TestNativeHTTPFlatBufferVerifier (the native AArch64 verifier vectors).

func TestHTTPParametersAndBounds(t *testing.T) {
	h := router.HTTPHeader{CheaterID: 3, CustomID: 1, Domain: "vpn.test", Extra: "opaque"}
	b, e := router.MarshalHTTPHeader(h)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseHTTPParameters(3, b)
	if e != nil || got != (HTTPHeader{CheaterID: 3, CustomID: 1, Domain: "vpn.test", Extra: "opaque"}) {
		t.Fatal(got, e)
	}
	for _, p := range []string{"evil\r\nHost: bad", "x\x00y", "a b", "https://a"} {
		if _, e := ParseHTTPParameters(2, []byte(p)); e == nil {
			t.Fatal("bad domain accepted")
		}
	}
	if got, e := ParseHTTPParameters(1, []byte("plain.test")); e != nil || got != (HTTPHeader{CheaterID: 1, Domain: "plain.test"}) {
		t.Fatal("plain selector-1 domain", got, e)
	}
	if got, e := ParseHTTPParameters(2, []byte("plain.test")); e != nil || got != (HTTPHeader{CheaterID: 2, Domain: "plain.test"}) {
		t.Fatal("plain selector-2 domain", got, e)
	}
	if got, e := ParseHTTPParameters(2, nil); e != nil || got != (HTTPHeader{}) {
		t.Fatal("empty parameters", got, e)
	}
	if _, e = ParseHTTPParameters(4, b); e == nil {
		t.Fatal("bad factory accepted")
	}
	if _, e = ParseHTTPParameters(0, b); e == nil {
		t.Fatal("bad factory accepted")
	}
}

func TestNativeHTTPFlatBufferVerifier(t *testing.T) {
	b, e := os.ReadFile("testdata/http-verifier.json")
	if e != nil {
		t.Fatal(e)
	}
	var data struct {
		Cases []struct {
			Header   *router.HTTPHeader
			Hex      string
			Accepted bool
		}
	}
	if e = json.Unmarshal(b, &data); e != nil {
		t.Fatal(e)
	}
	if len(data.Cases) == 0 {
		t.Fatal("no verifier cases")
	}
	for i, v := range data.Cases {
		raw := unhex(t, v.Hex)
		parsed, e := router.ParseHTTPHeader(raw)
		if (e == nil) != v.Accepted {
			t.Fatalf("verifier case %d native %t error %v", i, v.Accepted, e)
		}
		if v.Header != nil {
			if parsed != *v.Header {
				t.Fatal("native verifier fields changed")
			}
			rebuilt, e := router.MarshalHTTPHeader(parsed)
			if e != nil || !bytes.Equal(rebuilt, raw) {
				t.Fatal("builder bytes differ", e)
			}
		}
	}
}

// The provider policy's 1.2 floor offers exactly the original native
// capture (TLS 1.3 and 1.2); an orbit (1.3) floor keeps offering 1.3 only.
func TestNativeTLSProviderFloorOffersCapturedVersions(t *testing.T) {
	b, err := os.ReadFile("testdata/native-tls.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			AES        bool   `json:"aes"`
			ServerName string `json:"server_name"`
			Hex        string `json:"hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range fixture.Cases {
		if !v.AES {
			continue
		}
		n++
		spec, err := nativeTLSSpec(&tls.Config{ServerName: v.ServerName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { return nil }})
		if err != nil || spec.TLSVersMin != tls.VersionTLS12 || spec.TLSVersMax != tls.VersionTLS13 {
			t.Fatal("provider floor", err)
		}
		got := normalizedNativeHello(t, captureHelloWith(t, &tls.Config{ServerName: v.ServerName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { return nil }}), false, false)
		want := normalizedNativeHello(t, unhex(t, v.Hex), false, net.ParseIP(v.ServerName) != nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("provider ClientHello differs from the native capture for %s", v.ServerName)
		}
		for _, floor := range []uint16{0, tls.VersionTLS13} {
			spec, err = nativeTLSSpec(&tls.Config{ServerName: v.ServerName, MinVersion: floor})
			if err != nil || spec.TLSVersMin != tls.VersionTLS13 {
				t.Fatal("the owned floor moved", floor, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("native AES fixture missing")
	}
}

func captureHelloWith(t *testing.T, tc *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() {
		_, err := nativeTLSClient(ctx, a, tc)
		done <- err
	}()
	if err := b.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(b, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if err := <-done; err == nil {
		t.Fatal("handshake unexpectedly succeeded without a server")
	}
	return append(header, body...)
}
