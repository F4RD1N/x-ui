package anytls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/features/policy"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestAnyTLSNativeClientToNativeTLSServer(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "custom"}[custom], func(t *testing.T) {
			password := "00112233-4455-6677-8899-aabbccddeeff"
			s, d := anyTLSNewTestServer(t, password, custom)
			crt, _ := cert.MustGenerate(nil, cert.DNSNames("anytls.test"))
			kp, err := tls.X509KeyPair(crt.ToPEM())
			if err != nil {
				t.Fatal(err)
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func() { defer wg.Done(); _ = s.Process(context.Background(), xnet.Network_TCP, conn, d) }()
				}
			}()
			defer func() { listener.Close(); s.Close(); wg.Wait() }()
			pad, _ := parsePadding(defaultPadding)
			pemCert, _ := crt.ToPEM()
			client := &Client{config: &Config{Address: "127.0.0.1", Port: uint32(listener.Addr().(*net.TCPAddr).Port), Password: password, UuidHashMiddle: custom, Tls: &xtls.Config{ServerName: "anytls.test", DisableSystemRoot: true, Certificate: []*xtls.Certificate{{Certificate: pemCert, Usage: xtls.Certificate_AUTHORITY_VERIFY}}}}, policy: policy.DefaultManager{}, padding: pad, done: make(chan struct{})}
			defer client.Close()
			dials := new(atomic.Int32)
			dialer := ctxBoundDialer{addr: listener.Addr().String(), dials: dials}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			for i := 0; i < 3; i++ {
				carrier, err := client.take(ctx, dialer)
				if err != nil {
					t.Fatal(err)
				}
				st, err := carrier.open(ctx, anyTLSAddress("echo.example", 443))
				if err != nil {
					t.Fatal(err)
				}
				_ = st.SetReadDeadline(time.Now().Add(3 * time.Second))
				payload := bytes.Repeat([]byte("TLS payload"), 5000)
				if _, err = st.Write(payload); err != nil {
					t.Fatal(err)
				}
				actual := make([]byte, len(payload))
				if _, err = io.ReadFull(st, actual); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, payload) {
					t.Fatal("TLS stream payload differs")
				}
				st.Close()
			}
			if dials.Load() != 1 {
				t.Fatalf("idle carrier did not reuse session: %d dials", dials.Load())
			}
			// Ordinary certificate checking remains enabled unless explicitly overridden.
			rejecting := &Client{config: &Config{Address: "127.0.0.1", Port: client.config.Port, Password: password, Tls: &xtls.Config{ServerName: "wrong.test"}}, policy: policy.DefaultManager{}, padding: pad, done: make(chan struct{})}
			defer rejecting.Close()
			if carrier, err := rejecting.take(ctx, dialer); err == nil {
				carrier.fail(net.ErrClosed)
				t.Fatal("untrusted/wrong-name TLS certificate accepted")
			}
		})
	}
}

// Supply the genuine upstream executable explicitly; production has no
// dependency on this test fixture or any external AnyTLS process.
func TestAnyTLSNativeClientReferenceServerHTTP(t *testing.T) {
	binary := os.Getenv("ANYTLS_REFERENCE_SERVER")
	if binary == "" {
		t.Skip("set ANYTLS_REFERENCE_SERVER for independent stock server interoperability")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("independent-reference-round-trip"))
	}))
	defer target.Close()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserve.Addr().String()
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-l", address, "-p", "fixture-password")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	ready := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("reference fixture failed to listen")
	}
	pad, _ := parsePadding(defaultPadding)
	client := &Client{config: &Config{Address: "127.0.0.1", Port: uint32(port), Password: "fixture-password", Tls: &xtls.Config{ServerName: "localhost", AllowInsecure: true}}, policy: policy.DefaultManager{}, padding: pad, done: make(chan struct{})}
	defer client.Close()
	carrier, err := client.take(ctx, ctxBoundDialer{addr: address, dials: new(atomic.Int32)})
	if err != nil {
		t.Fatal(err)
	}
	targetAddr := target.Listener.Addr().(*net.TCPAddr)
	st, err := carrier.open(ctx, append([]byte{1, 127, 0, 0, 1}, byte(targetAddr.Port>>8), byte(targetAddr.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(st, "GET / HTTP/1.1\r\nHost: 127.0.0.1:"+strconv.Itoa(targetAddr.Port)+"\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("200 OK")) || !bytes.Contains(response, []byte("independent-reference-round-trip")) {
		t.Fatalf("reference HTTP round trip failed: %q", response)
	}
}

func TestAnyTLSReferenceClientToNativeTLSServer(t *testing.T) {
	binary := os.Getenv("ANYTLS_REFERENCE_CLIENT")
	if binary == "" {
		t.Skip("set ANYTLS_REFERENCE_CLIENT to the independent testdata/reference-client fixture")
	}
	s, d := anyTLSNewTestServer(t, "fixture-password", false)
	crt, _ := cert.MustGenerate(nil, cert.DNSNames("anytls.test"))
	kp, err := tls.X509KeyPair(crt.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); _ = s.Process(context.Background(), xnet.Network_TCP, conn, d) }()
		}
	}()
	defer func() { listener.Close(); s.Close(); wg.Wait() }()
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-server", listener.Addr().String(), "-password", "fixture-password", "-network", network)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("independent client failed: %v: %s", err, output)
			}
			if !bytes.Contains(output, []byte("three payload round trips passed")) {
				t.Fatalf("missing client verification: %s", output)
			}
		})
	}
}
