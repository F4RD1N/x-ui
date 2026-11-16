package metrics

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xtls/xray-core/common/clientsample"
)

func TestServeClientIPs(t *testing.T) {
	before := clientsample.Recorded()
	clientsample.Record(net.IP{198, 51, 100, 7})
	clientsample.Record(net.ParseIP("2001:db8::7"))

	rec := httptest.NewRecorder()
	serveClientIPs(rec, httptest.NewRequest(http.MethodGet, "/debug/clientips", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	var got struct {
		V        int      `json:"v"`
		Recorded uint64   `json:"recorded"`
		IPs      []string `json:"ips"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	n := len(got.IPs)
	if got.V != 1 || got.Recorded != before+2 || n < 2 ||
		got.IPs[n-2] != "198.51.100.7" || got.IPs[n-1] != "2001:db8::7" {
		t.Fatalf("got %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	serveClientIPs(rec, httptest.NewRequest(http.MethodPost, "/debug/clientips", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", rec.Code)
	}
}
