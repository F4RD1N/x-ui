package orbit

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestOuterCertificateFailureIsNotAPinMismatch: a WSS front whose
// certificate does not verify against the system roots is reported as that,
// whatever the fingerprint (crypto/tls or uTLS), never as a wrong key.
func TestOuterCertificateFailureIsNotAPinMismatch(t *testing.T) {
	front := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer front.Close()
	port := front.Listener.Addr().(*net.TCPAddr).Port
	for _, fp := range []string{"unsafe", "chrome", ""} {
		c, err := Settings{Address: "127.0.0.1", Port: uint32(port), Key: testKey(t), Transport: "wss", Host: "cdn.example.com",
			Path: "/core", Fingerprint: fp}.Config(3, "")
		if err != nil {
			t.Fatal(err)
		}
		plan, err := newDialPlan(c)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = plan.dial(ctx, new(netDialer))
		cancel()
		if err == nil {
			t.Fatalf("fp %q: an untrusted front was accepted", fp)
		}
		msg := err.Error()
		if strings.Contains(msg, "pin") || !strings.Contains(msg, "front (host) failed verification") {
			t.Fatalf("fp %q: %v", fp, err)
		}
	}
}
