package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/pki"
)

// normalizedNativeHello retains every deterministic wire field. Only actual
// entropy (random/session ID/X25519 share) is zeroed. Native supported_versions
// is filtered to TLS13 to model the owned runtime's deliberate security floor.
func normalizedNativeHello(t *testing.T, wire []byte, native, omitSNI bool) []byte {
	t.Helper()
	if len(wire) < 44 || wire[0] != 22 || wire[5] != 1 || int(binary.BigEndian.Uint16(wire[3:5])) != len(wire)-5 {
		t.Fatal("invalid ClientHello record")
	}
	b := bytes.Clone(wire[9:])
	clear(b[2:34])
	offset := 35 + int(b[34])
	clear(b[35:offset])
	offset += 2 + int(binary.BigEndian.Uint16(b[offset:offset+2]))
	offset += 1 + int(b[offset])
	extensions := b[offset+2:]
	if int(binary.BigEndian.Uint16(b[offset:offset+2])) != len(extensions) {
		t.Fatal("invalid ClientHello extensions")
	}
	var out []byte
	for len(extensions) > 0 {
		kind, n := binary.BigEndian.Uint16(extensions), int(binary.BigEndian.Uint16(extensions[2:]))
		value := bytes.Clone(extensions[4 : 4+n])
		extensions = extensions[4+n:]
		if kind == 0 && omitSNI {
			continue
		}
		if kind == 51 { // Only public-key bytes vary; vector/group/size must match.
			for pos := 2; pos < len(value); {
				size := int(binary.BigEndian.Uint16(value[pos+2:]))
				clear(value[pos+4 : pos+4+size])
				pos += 4 + size
			}
		}
		if kind == 43 && native {
			value = []byte{2, 3, 4}
		}
		out = binary.BigEndian.AppendUint16(out, kind)
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
	}
	b = append(binary.BigEndian.AppendUint16(b[:offset], uint16(len(out))), out...)
	result := []byte{wire[0], wire[1], wire[2]}
	result = binary.BigEndian.AppendUint16(result, uint16(len(b)+4))
	result = append(result, 1, byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	return append(result, b...)
}

func captureNativeHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() {
		_, err := nativeTLSClient(ctx, a, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13})
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

func TestNativeTLSClientHelloMatchesOriginalAESProfile(t *testing.T) {
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
		got := normalizedNativeHello(t, captureNativeHello(t, v.ServerName), false, false)
		want := normalizedNativeHello(t, unhex(t, v.Hex), true, net.ParseIP(v.ServerName) != nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("native ClientHello mismatch for%s\ngot %x\nwant%x", v.ServerName, got, want)
		}
	}
	if n == 0 {
		t.Fatal("native AES fixture missing")
	}
}

func pinnedNativeTLS(t *testing.T, st *tls.Config) *tls.Config {
	t.Helper()
	leaf, err := x509.ParseCertificate(st.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		leaf.IsCA = false
		leaf.KeyUsage = x509.KeyUsageDigitalSignature
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		key := st.Certificates[0].PrivateKey.(crypto.Signer)
		der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
		if e != nil {
			t.Fatal(e)
		}
		st.Certificates[0].Certificate = [][]byte{der}
		leaf, e = x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	ct, err := pki.ClientTLS("vpn.test", hex.EncodeToString(pin[:]))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestNativeTLSPinnedHTTPDuplexAndCurveRetry(t *testing.T) {
	for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384} {
		t.Run(curve.String(), func(t *testing.T) {
			st, _ := testTLS(t)
			st.MinVersion = tls.VersionTLS13
			st.CurvePreferences = []tls.CurveID{curve}
			ct := pinnedNativeTLS(t, st)
			var verified atomic.Int32
			verify := ct.VerifyConnection
			ct.VerifyConnection = func(s tls.ConnectionState) error {
				if s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "" {
					return errors.New("native TLS policy changed")
				}
				verified.Add(1)
				return verify(s)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				raw, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				c, proxy, err := HTTPServer(ctx, raw, HTTPServerOptions{TLSConfig: st})
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				if string(proxy) != "synthetic route" {
					done <- errors.New("proxy changed")
					return
				}
				_, err = io.Copy(c, c)
				done <- err
			}()
			raw, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			c, err := HTTPClient(ctx, raw, HTTPOptions{Options: Options{ProxyBuffer: []byte("synthetic route")}, Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, Path: "/", TLSConfig: ct, NativeTLS: true})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			payload := bytes.Repeat([]byte("native-tls\x00\xff"), 8192)
			written := make(chan error, 1)
			go func() { _, e := c.Write(payload); written <- e }()
			out := make([]byte, len(payload))
			if _, err = io.ReadFull(c, out); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, payload) || verified.Load() != 1 {
				t.Fatal("data or pin verification changed")
			}
			if err = <-written; err != nil {
				t.Fatal(err)
			}
			if err = c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeTLSPinFailureAndCancellation(t *testing.T) {
	for _, failure := range []string{"wrong-pin", "wrong-name", "untrusted"} {
		t.Run(failure, func(t *testing.T) {
			st, _ := testTLS(t)
			ct := pinnedNativeTLS(t, st)
			if failure == "wrong-pin" {
				var err error
				ct, err = pki.ClientTLS("vpn.test", hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure == "wrong-name" {
				leaf, _ := x509.ParseCertificate(st.Certificates[0].Certificate[0])
				pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				var err error
				ct, err = pki.ClientTLS("wrong.test", hex.EncodeToString(pin[:]))
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure == "untrusted" {
				ct = &tls.Config{ServerName: "vpn.test"}
			}
			a, b := net.Pipe()
			done := make(chan error, 1)
			go func() {
				_, _, e := HTTPServer(context.Background(), b, HTTPServerOptions{Options: Options{Timeout: time.Second}, TLSConfig: st})
				done <- e
			}()
			_, err := HTTPClient(context.Background(), a, HTTPOptions{Options: Options{Timeout: time.Second}, Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, TLSConfig: ct, NativeTLS: true})
			if err == nil {
				t.Fatal("invalid trust accepted")
			}
			if err = <-done; err == nil {
				t.Fatal("server accepted rejected client")
			}
		})
	}
	for _, cancelNow := range []bool{false, true} {
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		if cancelNow {
			cancel()
		}
		start := time.Now()
		_, err := HTTPClient(ctx, a, HTTPOptions{Options: Options{Timeout: 30 * time.Millisecond}, Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, NativeTLS: true})
		cancel()
		b.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatal("silent TLS did not stop promptly", err)
		}
	}
}

func TestNativeTLSRejectsUnsupportedEmbedding(t *testing.T) {
	for _, tc := range []*tls.Config{
		nil, {InsecureSkipVerify: true}, {MaxVersion: tls.VersionTLS12},
		{MinVersion: tls.VersionTLS13 + 1}, {NextProtos: []string{"h2"}},
		{CurvePreferences: []tls.CurveID{tls.CurveP256}}, {CipherSuites: []uint16{0xc02f}},
		{SessionTicketsDisabled: true}, {ClientSessionCache: tls.NewLRUClientSessionCache(1)},
		{Certificates: []tls.Certificate{{}}}, {Renegotiation: tls.RenegotiateOnceAsClient},
		{EncryptedClientHelloConfigList: []byte{1}},
	} {
		if _, err := nativeTLSSpec(tc); !errors.Is(err, errNativeTLSConfig) {
			t.Fatal("unsupported TLS options accepted", err)
		}
	}
}

func TestNativeTLSIPIdentityAndVerificationCallbacks(t *testing.T) {
	st, _ := testTLS(t)
	pinnedNativeTLS(t, st) // Replace the generic test CA with an owned leaf/IP SAN.
	leaf, err := x509.ParseCertificate(st.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	ct, err := pki.ClientTLS("127.0.0.1", hex.EncodeToString(pin[:]))
	if err != nil {
		t.Fatal(err)
	}
	var peerChecks, connectionChecks atomic.Int32
	ct.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if len(raw) != 1 || !bytes.Equal(raw[0], leaf.Raw) {
			return errors.New("peer certificate changed")
		}
		peerChecks.Add(1)
		return nil
	}
	verify := ct.VerifyConnection
	ct.VerifyConnection = func(s tls.ConnectionState) error { connectionChecks.Add(1); return verify(s) }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		raw, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer raw.Close()
		c := tls.Server(raw, st)
		e = c.HandshakeContext(ctx)
		if e == nil && c.ConnectionState().ServerName != "" {
			e = errors.New("literal IP was sent as SNI")
		}
		done <- e
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err = nativeTLSClient(ctx, raw, ct); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if peerChecks.Load() != 1 || connectionChecks.Load() != 1 {
		t.Fatal("verification callback not preserved")
	}
}

func TestNativeTLSCancelAfterClientHello(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := HTTPClient(ctx, a, HTTPOptions{Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, NativeTLS: true})
		done <- e
	}()
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(b, header); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, b, int64(binary.BigEndian.Uint16(header[3:]))); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel did not propagate", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client remained blocked after cancellation")
	}
}
