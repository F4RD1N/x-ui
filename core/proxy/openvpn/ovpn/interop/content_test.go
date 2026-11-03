package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Known answers: the first bytes were computed independently (SplitMix64 in
// Python); the digests are what the live test server served.
func TestBlobKnownAnswers(t *testing.T) {
	head, err := io.ReadAll(NewBlobReader(32, 7))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(head), "d70d3259e4e1cb631c663cf4d73c4c04022ab1ba804098e6cb293e6770eb3a95"; got != want {
		t.Errorf("blob(32, 7) = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(sha(BlobSHA256(4000000, 7))), "76d664f68a5a8efc4ab76b759b1aea327802a42f52e20c8ebea2e9b494216ce4"; got != want {
		t.Errorf("BlobSHA256(4000000, 7) = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(sha(TextSHA256(2000000))), "ef112366a0f8a050ef0992b796bca792df882af5cd76fae7ac2798fa4d4fb10b"; got != want {
		t.Errorf("TextSHA256(2000000) = %s, want %s", got, want)
	}
}

func sha(s [32]byte) []byte { return s[:] }

// readChunked reads r with a cycle of awkward buffer sizes.
func readChunked(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var out []byte
	sizes := []int{1, 3, 7, 8, 9, 15, 16, 17, 1000}
	for i := 0; ; i++ {
		buf := make([]byte, sizes[i%len(sizes)])
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadersChunking(t *testing.T) {
	for _, size := range []int64{0, 1, 7, 8, 9, 63, 64, 65, 1000, 4099} {
		whole, _ := io.ReadAll(NewBlobReader(size, 99))
		if int64(len(whole)) != size {
			t.Fatalf("blob size %d: read %d bytes", size, len(whole))
		}
		if got := readChunked(t, NewBlobReader(size, 99)); !bytes.Equal(got, whole) {
			t.Errorf("blob size %d: chunked read differs", size)
		}
		text, _ := io.ReadAll(NewTextReader(size))
		if int64(len(text)) != size {
			t.Fatalf("text size %d: read %d bytes", size, len(text))
		}
		if got := readChunked(t, NewTextReader(size)); !bytes.Equal(got, text) {
			t.Errorf("text size %d: chunked read differs", size)
		}
	}
	if b, _ := io.ReadAll(NewBlobReader(-5, 1)); len(b) != 0 {
		t.Errorf("negative size read %d bytes", len(b))
	}
	text, _ := io.ReadAll(NewTextReader(200))
	if !strings.HasPrefix(string(text), "00000000 the quick brown fox") || !strings.Contains(string(text), "\n00000001 ") {
		t.Errorf("text = %q", text)
	}
	if a, b := BlobSHA256(1000, 1), BlobSHA256(1000, 2); a == b {
		t.Error("different seeds give the same blob")
	}
}

func get(t *testing.T, base, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp.StatusCode, body
}

func TestHandler(t *testing.T) {
	srv := httptest.NewServer(NewTestHandler())
	defer srv.Close()

	if code, body := get(t, srv.URL, "/hello"); code != 200 || string(body) != HelloBody {
		t.Errorf("/hello = %d %q", code, body)
	}
	code, body := get(t, srv.URL, "/blob?size=100000&seed=7")
	if code != 200 || sha256.Sum256(body) != BlobSHA256(100000, 7) {
		t.Errorf("/blob = %d, %d bytes, wrong content", code, len(body))
	}
	code, body = get(t, srv.URL, "/text?size=12345")
	if code != 200 || sha256.Sum256(body) != TextSHA256(12345) {
		t.Errorf("/text = %d, %d bytes, wrong content", code, len(body))
	}
	if code, body := get(t, srv.URL, "/ip"); code != 200 || string(body) != "127.0.0.1\n" {
		t.Errorf("/ip = %d %q", code, body)
	}
	payload := bytes.Repeat([]byte("echo!"), 50000)
	resp, err := http.Post(srv.URL+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	echoed, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(echoed, payload) {
		t.Errorf("/echo = %d, %d bytes", resp.StatusCode, len(echoed))
	}

	for _, bad := range []string{
		"/blob", "/blob?size=-1", "/blob?size=x", fmt.Sprintf("/blob?size=%d", int64(MaxContentSize)+1),
		"/blob?size=10&seed=-1", "/text?size=10&rate=5", "/text?size=10&rate=x",
	} {
		if code, _ := get(t, srv.URL, bad); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", bad, code)
		}
	}
	if code, _ := get(t, srv.URL, "/nothing"); code != http.StatusNotFound {
		t.Errorf("/nothing = %d, want 404", code)
	}

	// Pacing: 40 KB at 100 KB/s takes about 0.4 s.
	start := time.Now()
	code, body = get(t, srv.URL, "/blob?size=40000&seed=3&rate=100000")
	if d := time.Since(start); code != 200 || len(body) != 40000 || d < 250*time.Millisecond || d > 5*time.Second {
		t.Errorf("paced /blob = %d, %d bytes in %v", code, len(body), d)
	}
	if sha256.Sum256(body) != BlobSHA256(40000, 3) {
		t.Error("paced /blob content differs")
	}
}

func TestServeUDPEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ServeUDPEcho(pc) }()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, msg := range []string{"a", strings.Repeat("b", 1300), "c"} {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2000)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo of %d bytes: %d bytes, %v", len(msg), n, err)
		}
	}
	pc.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeUDPEcho did not return after Close")
	}
}

const sampleCases = `[
  {"name": "udp-a", "ovpn": "/x/a.ovpn", "username": "", "password": "", "proto": "udp", "port": 1194,
   "tunnelServerIP": "10.81.0.1", "tunnelServerIPv6": "fd81::1", "cipher": "AES-256-GCM", "tlsVersion": "TLS 1.3",
   "compression": "", "serverLog": "/x/a.log", "notes": "n"},
  {"name": "tcp-b", "ovpn": "/x/b.ovpn", "username": "u", "password": "p", "proto": "tcp", "port": 1195,
   "tunnelServerIP": "10.82.0.1", "tunnelServerIPv6": "", "cipher": "AES-128-CBC", "tlsVersion": "TLS 1.2",
   "compression": "lzo", "serverLog": "/x/b.log", "notes": ""}
]`

func TestParseCases(t *testing.T) {
	cases, err := parseCases([]byte(sampleCases))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || cases[0].Name != "udp-a" || cases[1].Username != "u" || !cases[1].IsCompressionCase() {
		t.Fatalf("cases = %+v", cases)
	}
	if a := cases[0].TestServer(true); a.String() != "fd81::1" {
		t.Errorf("TestServer(v6) = %v", a)
	}
	if a := cases[1].TestServer(true); a.IsValid() {
		t.Errorf("TestServer(v6) without IPv6 = %v", a)
	}
	if got := cases[1].ServerAddr(); got != "10.213.0.2:1195" {
		t.Errorf("ServerAddr = %s", got)
	}
	for _, bad := range []string{
		``, `{}`, `[{}]`,
		`[{"name":"a","ovpn":"x","proto":"sctp","port":1,"tunnelServerIP":"10.0.0.1"}]`,
		`[{"name":"a","ovpn":"x","proto":"udp","port":0,"tunnelServerIP":"10.0.0.1"}]`,
		`[{"name":"a","ovpn":"x","proto":"udp","port":1,"tunnelServerIP":"fd00::1"}]`,
		`[{"name":"a","ovpn":"x","proto":"udp","port":1,"tunnelServerIP":"10.0.0.1","tunnelServerIPv6":"10.0.0.2"}]`,
		`[{"name":"a","ovpn":"x","proto":"udp","port":1,"tunnelServerIP":"10.0.0.1"},{"name":"a","ovpn":"y","proto":"udp","port":2,"tunnelServerIP":"10.0.0.1"}]`,
	} {
		if _, err := parseCases([]byte(bad)); err == nil {
			t.Errorf("parseCases(%q) succeeded", bad)
		}
	}
}

// TestHarnessCasesFile checks cases.json when the harness has written one.
func TestHarnessCasesFile(t *testing.T) {
	cases, err := LoadCases()
	if err != nil {
		t.Skipf("no harness cases.json: %v", err)
	}
	if len(cases) != 11 {
		t.Errorf("cases.json has %d cases, want 11", len(cases))
	}
	for i, c := range cases {
		if c.Port != 1194+i {
			t.Errorf("case %d %s: port %d, want %d", i, c.Name, c.Port, 1194+i)
		}
		if want := fmt.Sprintf("10.%d.0.1", 81+i); c.TunnelServerIP != want {
			t.Errorf("case %s: tunnelServerIP %s, want %s", c.Name, c.TunnelServerIP, want)
		}
	}
}

// TestDial reaches the test server on the namespace address from the client
// namespace, over TCP and UDP, IPv4 and IPv6.
func TestDial(t *testing.T) {
	Require(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, host := range []string{ServerIP, "fd00:213::2"} {
		c, err := Dial(ctx, "tcp", net.JoinHostPort(host, "8080"))
		if err != nil {
			t.Fatalf("Dial tcp %s: %v", host, err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "GET /ip HTTP/1.0\r\n\r\n")
		resp, _ := io.ReadAll(c)
		c.Close()
		want := "10.214.0.2\n"
		if strings.Contains(host, ":") {
			want = "fd00:214::2\n"
		}
		if !strings.HasSuffix(string(resp), "\r\n\r\n"+want) {
			t.Errorf("GET /ip via %s = %q, want body %q", host, resp, want)
		}
		u, err := Dial(ctx, "udp", net.JoinHostPort(host, "5353"))
		if err != nil {
			t.Fatalf("Dial udp %s: %v", host, err)
		}
		u.SetDeadline(time.Now().Add(5 * time.Second))
		u.Write([]byte("dial-echo"))
		buf := make([]byte, 64)
		n, err := u.Read(buf)
		u.Close()
		if err != nil || string(buf[:n]) != "dial-echo" {
			t.Errorf("UDP echo via %s: %q, %v", host, buf[:n], err)
		}
	}
	if _, err := Dial(ctx, "tcp", "localhost:80"); err == nil {
		t.Error("Dial accepted a host name")
	}
}

func FuzzParseCases(f *testing.F) {
	f.Add([]byte(sampleCases))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"name":"a"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		cases, err := parseCases(b)
		if err != nil {
			return
		}
		if len(cases) > maxCases {
			t.Fatalf("%d cases accepted", len(cases))
		}
		for _, c := range cases {
			if !c.TestServer(false).Is4() || c.Port <= 0 || c.Port > 65535 {
				t.Fatalf("invalid case accepted: %+v", c)
			}
		}
	})
}

// FuzzHandler throws arbitrary paths and queries at the test server's
// handler (sizes capped, pacing off).
func FuzzHandler(f *testing.F) {
	for _, s := range []string{"/hello", "/blob?size=100&seed=1", "/text?size=77&rate=2048", "/ip", "/blob?size=99999999999999999999", "/text?size=1&size=2", "/blob?seed=%zz"} {
		f.Add("GET", s, []byte(nil))
	}
	f.Add("POST", "/echo", []byte("body"))
	const limit = 1 << 16
	h := newHandler(limit, false)
	f.Fuzz(func(t *testing.T, method, target string, body []byte) {
		path, query, _ := strings.Cut(target, "?")
		req := httptest.NewRequest("GET", "/", bytes.NewReader(body))
		req.Method = method
		req.URL.Path = path
		req.URL.RawPath = ""
		req.URL.RawQuery = query
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Body.Len() > limit+1024 {
			t.Fatalf("%s %q: %d bytes, more than the limit", method, target, rec.Body.Len())
		}
	})
}
