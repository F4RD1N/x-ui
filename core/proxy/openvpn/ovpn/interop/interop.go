// Package interop runs the OpenVPN client against stock OpenVPN 2.6 servers.
//
// harness.sh (next to this file) brings up network namespace "ovpntest",
// joined to the host by veth ovt0 (host, 10.213.0.1/24) and ovt1 (namespace,
// 10.213.0.2/24), with one OpenVPN 2.6 server per case and a test server
// (testsrv) inside it. Everything it generates lives in Dir() (default
// /tmp/ovpn-interop), including cases.json, which Cases reads.
//
// Tests call Require first: it skips unless OVPN_INTEROP=1 and the test runs
// as root, and brings the harness up (harness.sh up) when harness.sh status
// says it is not. A client reaches the test server at the case's server
// tunnel address (Case.TunnelServerIP, and Case.TunnelServerIPv6 for the case
// with IPv6 inside the tunnel) on HTTPPort and UDPEchoPort.
//
// Clients must dial the servers with Dial, which creates its sockets in the
// client namespace "ovpncli" (veth to ovpntest, routes to 10.213.0.0/24 and
// fd00:213::/64): the host's own firewall may drop host traffic to private
// addresses, so dialing 10.213.0.2 from the host namespace is not reliable.
//
// Run the acceptance tests (interop_test.go) with
//
//	OVPN_INTEROP=1 ovpn-gorun go test -count=1 -timeout 900s -v ./proxy/openvpn/ovpn/interop/
//
// and check the harness itself with the real OpenVPN client using
// validate-real-client.sh.
//
// The test server (NewTestHandler, ServeUDPEcho) answers:
//
//	GET  /hello                      HelloBody
//	GET  /blob?size=N&seed=S[&rate=R] N bytes of NewBlobReader(N, S)
//	GET  /text?size=N[&rate=R]        N bytes of NewTextReader(N)
//	GET  /ip                          the client's address and "\n"
//	POST /echo                        the request body
//	UDP  :5353                        every datagram back to its sender
//
// rate, when given, paces the response to about R bytes per second.
package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixed parameters of the harness.
const (
	Namespace = "ovpntest"
	// ClientNamespace is where Dial creates sockets.
	ClientNamespace = "ovpncli"
	HostIP          = "10.213.0.1" // host end of the veth (ovt0)
	ServerIP        = "10.213.0.2" // namespace end (ovt1): where clients connect
	HTTPPort        = 8080
	UDPEchoPort     = 5353
	HelloBody       = "hello from ovpntest\n"
	// Username and Password are the credentials the servers' auth script
	// accepts.
	Username = "ovpnuser"
	Password = "s3cret-pass"
)

// Case is one OpenVPN server of the harness: one entry of cases.json.
type Case struct {
	Name string `json:"name"`
	// OVPN is the path of the client configuration, every key inline.
	OVPN string `json:"ovpn"`
	// Username and Password are set for the cases that check them.
	Username string `json:"username"`
	Password string `json:"password"`
	Proto    string `json:"proto"` // "udp" or "tcp"
	Port     int    `json:"port"`
	// TunnelServerIP is the server's address inside the tunnel, where the
	// test server answers; TunnelServerIPv6 likewise, "" when the case
	// carries no IPv6.
	TunnelServerIP   string `json:"tunnelServerIP"`
	TunnelServerIPv6 string `json:"tunnelServerIPv6"`
	// What the session should negotiate: the data cipher (canonical name)
	// and the TLS version ("TLS 1.3", "TLS 1.2").
	Cipher     string `json:"cipher"`
	TLSVersion string `json:"tlsVersion"`
	// Compression the server pushes: "lz4-v2", "lzo", "stub" or "".
	Compression string `json:"compression"`
	// ServerLog is the server's log file (verb 4).
	ServerLog string `json:"serverLog"`
	Notes     string `json:"notes"`
}

// ReadOVPN returns the client configuration text.
func (c Case) ReadOVPN() (string, error) {
	b, err := os.ReadFile(c.OVPN)
	if err != nil {
		return "", fmt.Errorf("interop: case %s: %w", c.Name, err)
	}
	return string(b), nil
}

// ServerAddr is host:port of the OpenVPN server.
func (c Case) ServerAddr() string { return net.JoinHostPort(ServerIP, strconv.Itoa(c.Port)) }

// TestServer returns the test server's tunnel address: IPv4, or IPv6 when v6
// is set. The address is invalid when the case has none.
func (c Case) TestServer(v6 bool) netip.Addr {
	s := c.TunnelServerIP
	if v6 {
		s = c.TunnelServerIPv6
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// ServerLogSize is the current size of the server log, for ServerLogSince.
func (c Case) ServerLogSize() int64 {
	fi, err := os.Stat(c.ServerLog)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// ServerLogSince returns what the server logged from offset on.
func (c Case) ServerLogSince(offset int64) (string, error) {
	f, err := os.Open(c.ServerLog)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<20))
	return string(b), err
}

// Dir is $OVPN_INTEROP_DIR, default /tmp/ovpn-interop.
func Dir() string {
	if d := os.Getenv("OVPN_INTEROP_DIR"); d != "" {
		return d
	}
	return "/tmp/ovpn-interop"
}

// Script is the path of harness.sh ($OVPN_INTEROP_HARNESS overrides it).
func Script() string {
	if s := os.Getenv("OVPN_INTEROP_HARNESS"); s != "" {
		return s
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "harness.sh"
	}
	return filepath.Join(filepath.Dir(file), "harness.sh")
}

// Enabled reports whether interop tests may run (OVPN_INTEROP=1 and root)
// and, when not, why.
func Enabled() (bool, string) {
	if os.Getenv("OVPN_INTEROP") != "1" {
		return false, "OpenVPN interop tests need OVPN_INTEROP=1 (and root)"
	}
	if os.Geteuid() != 0 {
		return false, "OpenVPN interop tests need root"
	}
	return true, ""
}

var (
	upOnce  sync.Once
	upErr   error
	upCases []Case
)

// Require skips t unless interop tests are enabled, and otherwise makes sure
// the harness is up (once per process), failing t when it cannot be brought
// up or cases.json is unusable.
func Require(t testing.TB) {
	t.Helper()
	if ok, why := Enabled(); !ok {
		t.Skip(why)
	}
	upOnce.Do(func() { upCases, upErr = bringUp() })
	if upErr != nil {
		t.Fatalf("interop harness: %v", upErr)
	}
}

func bringUp() ([]Case, error) {
	script := Script()
	if err := runScript(script, "status", 30*time.Second); err != nil {
		if err := runScript(script, "up", 10*time.Minute); err != nil {
			return nil, err
		}
	}
	cases, err := LoadCases()
	if err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, errors.New("cases.json lists no cases")
	}
	return cases, nil
}

func runScript(script, cmd string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "bash", script, cmd)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	c.WaitDelay = 5 * time.Second
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %v\n%s", script, cmd, err, out.String())
	}
	return nil
}

// LoadCases reads Dir()/cases.json.
func LoadCases() ([]Case, error) {
	b, err := os.ReadFile(filepath.Join(Dir(), "cases.json"))
	if err != nil {
		return nil, fmt.Errorf("interop: %w", err)
	}
	return parseCases(b)
}

// maxCases bounds cases.json; the harness writes eleven.
const maxCases = 64

func parseCases(b []byte) ([]Case, error) {
	var cases []Case
	if err := json.Unmarshal(b, &cases); err != nil {
		return nil, fmt.Errorf("interop: cases.json: %w", err)
	}
	if len(cases) > maxCases {
		return nil, fmt.Errorf("interop: cases.json: %d cases, at most %d", len(cases), maxCases)
	}
	seen := make(map[string]bool, len(cases))
	for i, c := range cases {
		switch {
		case c.Name == "":
			return nil, fmt.Errorf("interop: cases.json: case %d has no name", i)
		case seen[c.Name]:
			return nil, fmt.Errorf("interop: cases.json: duplicate case %q", c.Name)
		case c.OVPN == "":
			return nil, fmt.Errorf("interop: cases.json: case %s has no ovpn", c.Name)
		case c.Proto != "udp" && c.Proto != "tcp":
			return nil, fmt.Errorf("interop: cases.json: case %s: proto %q", c.Name, c.Proto)
		case c.Port <= 0 || c.Port > 65535:
			return nil, fmt.Errorf("interop: cases.json: case %s: port %d", c.Name, c.Port)
		case !c.TestServer(false).Is4():
			return nil, fmt.Errorf("interop: cases.json: case %s: tunnelServerIP %q", c.Name, c.TunnelServerIP)
		case c.TunnelServerIPv6 != "" && !c.TestServer(true).Is6():
			return nil, fmt.Errorf("interop: cases.json: case %s: tunnelServerIPv6 %q", c.Name, c.TunnelServerIPv6)
		}
		seen[c.Name] = true
	}
	return cases, nil
}

// Cases returns the harness cases in cases.json order: the list Require
// loaded, else a fresh read of cases.json; nil when that fails.
func Cases() []Case {
	if upCases != nil {
		return upCases
	}
	cases, err := LoadCases()
	if err != nil {
		return nil
	}
	return cases
}

// Lookup returns the case called name.
func Lookup(name string) (Case, bool) {
	for _, c := range Cases() {
		if c.Name == name {
			return c, true
		}
	}
	return Case{}, false
}

// ---------------------------------------------------------------- content

// NewBlobReader returns the size bytes /blob serves for seed: the
// little-endian 64-bit outputs of SplitMix64 started at state seed.
func NewBlobReader(size int64, seed uint64) io.Reader {
	return &blobReader{state: seed, left: max(size, 0)}
}

type blobReader struct {
	state uint64
	left  int64
	word  [8]byte
	pend  []byte // unread tail of word
}

func (r *blobReader) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *blobReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n := copy(p, r.pend)
	r.pend = r.pend[n:]
	for len(p)-n >= 8 {
		binary.LittleEndian.PutUint64(p[n:], r.next())
		n += 8
	}
	if n < len(p) {
		binary.LittleEndian.PutUint64(r.word[:], r.next())
		c := copy(p[n:], r.word[:])
		r.pend = r.word[c:]
		n += c
	}
	r.left -= int64(n)
	return n, nil
}

// BlobSHA256 is the SHA-256 of NewBlobReader(size, seed).
func BlobSHA256(size int64, seed uint64) [32]byte {
	return sum(NewBlobReader(size, seed))
}

// textLine is the template of /text: line i is fmt.Sprintf(textLine, i%1e8).
const textLine = "%08d the quick brown fox jumps over the lazy dog; ovpntest compressible text\n"

// NewTextReader returns the size bytes /text serves: lines of
// "%08d the quick brown fox ..." counting from 0, cut at size bytes.
func NewTextReader(size int64) io.Reader { return &textReader{left: max(size, 0)} }

type textReader struct {
	left int64
	line int
	buf  []byte // rest of the current line
}

func (r *textReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			r.buf = fmt.Appendf(r.buf[:0], textLine, r.line%100000000)
			r.line++
		}
		c := copy(p[n:], r.buf)
		r.buf = r.buf[c:]
		n += c
	}
	r.left -= int64(n)
	return n, nil
}

// TextSHA256 is the SHA-256 of NewTextReader(size).
func TextSHA256(size int64) [32]byte { return sum(NewTextReader(size)) }

func sum(r io.Reader) [32]byte {
	h := sha256.New()
	io.Copy(h, r) //nolint:errcheck // the readers never fail
	var s [32]byte
	h.Sum(s[:0])
	return s
}

// ---------------------------------------------------------------- test server

// MaxContentSize bounds the size parameter of /blob and /text, and the body
// /echo accepts.
const MaxContentSize = 1 << 30

// NewTestHandler returns the test server's HTTP handler.
func NewTestHandler() http.Handler { return newHandler(MaxContentSize, true) }

func newHandler(maxSize int64, pacing bool) http.Handler {
	h := &handler{maxSize: maxSize, pacing: pacing}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hello", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, HelloBody) //nolint:errcheck
	})
	mux.HandleFunc("GET /blob", h.blob)
	mux.HandleFunc("GET /text", h.text)
	mux.HandleFunc("GET /ip", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.Unmap().String()
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, host+"\n") //nolint:errcheck
	})
	mux.HandleFunc("POST /echo", h.echo)
	return mux
}

type handler struct {
	maxSize int64
	pacing  bool
}

// query reads the size, seed and rate parameters.
func (h *handler) query(r *http.Request) (size int64, seed uint64, rate int64, err error) {
	q := r.URL.Query()
	size, err = strconv.ParseInt(q.Get("size"), 10, 64)
	if err != nil || size < 0 || size > h.maxSize {
		return 0, 0, 0, fmt.Errorf("size must be 0..%d", h.maxSize)
	}
	if s := q.Get("seed"); s != "" {
		if seed, err = strconv.ParseUint(s, 10, 64); err != nil {
			return 0, 0, 0, errors.New("bad seed")
		}
	}
	if s := q.Get("rate"); s != "" {
		if rate, err = strconv.ParseInt(s, 10, 64); err != nil || rate < 1024 {
			return 0, 0, 0, errors.New("rate must be at least 1024 bytes per second")
		}
	}
	return size, seed, rate, nil
}

func (h *handler) blob(w http.ResponseWriter, r *http.Request) {
	size, seed, rate, err := h.query(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.serve(w, r, "application/octet-stream", size, rate, NewBlobReader(size, seed))
}

func (h *handler) text(w http.ResponseWriter, r *http.Request) {
	size, _, rate, err := h.query(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.serve(w, r, "text/plain", size, rate, NewTextReader(size))
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request, ctype string, size, rate int64, body io.Reader) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if rate == 0 || !h.pacing {
		io.Copy(w, body) //nolint:errcheck // the client went away
		return
	}
	// Paced: chunks of a tenth of a second, each sent when it is due.
	chunk := max(rate/10, 1024)
	buf := make([]byte, min(chunk, 64<<10))
	start := time.Now()
	var sent int64
	for sent < size {
		n, _ := io.ReadFull(body, buf[:min(int64(len(buf)), size-sent)])
		if _, err := w.Write(buf[:n]); err != nil {
			return
		}
		sent += int64(n)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		due := start.Add(time.Duration(float64(sent) / float64(rate) * float64(time.Second)))
		if d := time.Until(due); d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
	}
}

func (h *handler) echo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body) //nolint:errcheck
}

// ServeUDPEcho sends every datagram read from pc back to its sender until pc
// fails (is closed).
func ServeUDPEcho(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// One unreachable sender must not stop the echo.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
		}
	}
}

// IsCompressionCase reports whether the server compresses what it sends.
func (c Case) IsCompressionCase() bool {
	return c.Compression == "lz4-v2" || c.Compression == "lzo"
}

// String names the case for logs.
func (c Case) String() string {
	return c.Name + " (" + strings.ToUpper(c.Proto) + " " + strconv.Itoa(c.Port) + ")"
}
