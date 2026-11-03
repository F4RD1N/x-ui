package openvpn

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/openvpn/netstack"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// testCA is a self-signed P-256 certificate (valid until 2126) that
// makes testOVPN pass the TLS checks.
const testCA = `-----BEGIN CERTIFICATE-----
MIIBhDCCASugAwIBAgIUHD30Y4uRGPc/YjiWoyy/V3rTn0swCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMb3Zwbi10ZXN0LWNhMCAXDTI2MTAwOTAyMDAwMloYDzIxMjYw
OTE1MDIwMDAyWjAXMRUwEwYDVQQDDAxvdnBuLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARJUhV+m0C9fbu4bpwLbIbqSwHRoWEhzNoQWioyHINKtqt7
o3WY8A1X6kQTEa5ozQiTnCvMBPtj6aelWIm1C8eEo1MwUTAdBgNVHQ4EFgQUPuge
DMNAr1CVasIAGt0Xe+nS4GowHwYDVR0jBBgwFoAUPugeDMNAr1CVasIAGt0Xe+nS
4GowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB1PUsrOWXOY0ES
AGE45uOcnoxNOCi1iyNObiguEJ93yQIgIB9M8OKG3OWB6OIVJ2XhkP49gQFQXEKz
Uy/fcozAlmc=
-----END CERTIFICATE-----`

const badCA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

const testOVPN = "client\ndev tun\nproto udp\nremote 192.0.2.10 1194\nremote-cert-tls server\n<ca>\n" + testCA + "\n</ca>\n"

var (
	srvV4 = netip.MustParseAddr("10.9.0.1")
	srvV6 = netip.MustParseAddr("fd00:9::1")
	cliV4 = netip.MustParsePrefix("10.9.0.2/24")
	cliV6 = netip.MustParsePrefix("fd00:9::2/64")
)

const (
	echoTCPPort = 7
	echoUDPPort = 9
	waitLong    = 10 * time.Second
)

// ---------------------------------------------------------------- fake server

// fakeServer is the far end of a fake session: a gVisor stack with TCP echo
// on port 7 (both families) and UDP echo on port 9 (IPv4).
type fakeServer struct {
	stack *stack.Stack
	dev   tun.Device
	out   chan []byte // packets the server sends to the client
	once  sync.Once
	wg    sync.WaitGroup
}

func newFakeServer() (*fakeServer, error) {
	dev, _, s, err := gvisortun.CreateNetTUN([]netip.Addr{srvV4, srvV6}, 1500, false)
	if err != nil {
		return nil, err
	}
	f := &fakeServer{stack: s, dev: dev, out: make(chan []byte, 4096)}
	f.wg.Add(1)
	go f.pump()
	for _, a := range []netip.Addr{srvV4, srvV6} {
		pn := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if a.Is6() {
			pn = ipv6.ProtocolNumber
		}
		l, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: echoTCPPort}, pn)
		if err != nil {
			f.close()
			return nil, fmt.Errorf("listen %v: %v", a, err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}()
			}
		}()
	}
	u, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(srvV4.AsSlice()), Port: echoUDPPort}, nil, ipv4.ProtocolNumber)
	if err != nil {
		f.close()
		return nil, err
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = u.WriteTo(b[:n], addr)
		}
	}()
	return f, nil
}

func (f *fakeServer) pump() {
	defer f.wg.Done()
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := f.dev.Read(bufs, sizes, 0)
		if err != nil {
			if goerrors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if n < 1 {
			continue
		}
		select {
		case f.out <- bytes.Clone(bufs[0][:sizes[0]]):
		default:
		}
	}
}

func (f *fakeServer) close() {
	f.once.Do(func() {
		f.stack.Destroy()
		_ = f.dev.Close()
		f.wg.Wait()
	})
}

// ---------------------------------------------------------------- fake session

type fakeSession struct {
	info   client.TunnelInfo
	srv    *fakeServer // nil: packets go nowhere
	done   chan struct{}
	once   sync.Once
	err    error
	closes atomic.Int32
}

func newFakeSession(info client.TunnelInfo, srv *fakeServer) *fakeSession {
	return &fakeSession{info: info, srv: srv, done: make(chan struct{})}
}

func (s *fakeSession) Info() client.TunnelInfo { return s.info }

func (s *fakeSession) ReadPacket(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, s.err
	default:
	}
	var in chan []byte
	if s.srv != nil {
		in = s.srv.out
	}
	select {
	case pkt := <-in:
		n := copy(p, pkt)
		if n < len(pkt) {
			return n, io.ErrShortBuffer
		}
		return n, nil
	case <-s.done:
		return 0, s.err
	}
}

func (s *fakeSession) WritePacket(p []byte) error {
	select {
	case <-s.done:
		return s.err
	default:
	}
	if s.srv == nil {
		return nil
	}
	_, err := s.srv.dev.Write([][]byte{p}, 0)
	return err
}

func (s *fakeSession) Done() <-chan struct{} { return s.done }

func (s *fakeSession) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

func (s *fakeSession) Close() error {
	s.closes.Add(1)
	s.fail(client.ErrClosed)
	return nil
}

func (s *fakeSession) fail(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
		if s.srv != nil {
			s.srv.close()
		}
	})
}

// ---------------------------------------------------------------- fakes for Xray

type fakeDNS struct {
	answers map[string][]net.IP
	mu      sync.Mutex
	calls   []dns.IPOption
}

func (*fakeDNS) Type() interface{} { return dns.ClientType() }
func (*fakeDNS) Start() error      { return nil }
func (*fakeDNS) Close() error      { return nil }

func (d *fakeDNS) LookupIP(domain string, opt dns.IPOption) ([]net.IP, uint32, error) {
	d.mu.Lock()
	d.calls = append(d.calls, opt)
	d.mu.Unlock()
	var out []net.IP
	for _, ip := range d.answers[domain] {
		if (ip.To4() != nil && opt.IPv4Enable) || (ip.To4() == nil && opt.IPv6Enable) {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}
	return out, 0, nil
}

// fakeDialer hands out one end of a net.Pipe per dial and records what it
// was asked; release (when set) holds every dial until it is closed.
type fakeDialer struct {
	mu      sync.Mutex
	dests   []xnet.Destination
	ctxs    []context.Context
	conns   []*trackedConn
	err     error
	release chan struct{}
}

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (d *fakeDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	d.mu.Lock()
	d.dests = append(d.dests, dest)
	d.ctxs = append(d.ctxs, ctx)
	release, err := d.release, d.err
	d.mu.Unlock()
	if release != nil {
		<-release
	}
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	c := &trackedConn{Conn: a}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

func (*fakeDialer) Address() xnet.Address { return nil }
func (*fakeDialer) DestIpAddress() net.IP { return nil }

var _ internet.Dialer = (*fakeDialer)(nil)

// ---------------------------------------------------------------- fixture

type fixture struct {
	t      *testing.T
	h      *Handler
	dns    *fakeDNS
	dialer *fakeDialer

	mu       sync.Mutex
	info     client.TunnelInfo
	cfgs     []client.Config
	sessions []*fakeSession
	// hook runs inside dialSession before the session is made; an error
	// fails the dial.
	hook func(ctx context.Context, cfg client.Config) error
}

func newFixture(t *testing.T, conf *Config) *fixture {
	t.Helper()
	if conf == nil {
		conf = &Config{Ovpn: testOVPN}
	}
	f := &fixture{
		t: t,
		dns: &fakeDNS{answers: map[string][]net.IP{
			"echo.test": {net.IP(srvV4.AsSlice()), net.IP(srvV6.AsSlice())},
		}},
		dialer: &fakeDialer{},
		info:   client.TunnelInfo{IPv4: cliV4, IPv6: cliV6, MTU: 1500, Cipher: "AES-256-GCM"},
	}
	h, err := newHandler(conf, policy.DefaultManager{}, f.dns)
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	old := dialSession
	dialSession = f.dial
	t.Cleanup(func() {
		_ = h.Close()
		dialSession = old
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, s := range f.sessions {
			s.fail(client.ErrClosed)
		}
	})
	return f
}

func (f *fixture) dial(ctx context.Context, cfg client.Config) (vpnSession, error) {
	f.mu.Lock()
	f.cfgs = append(f.cfgs, cfg)
	hook, info := f.hook, f.info
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, cfg); err != nil {
			return nil, err
		}
	}
	srv, err := newFakeServer()
	if err != nil {
		return nil, err
	}
	s := newFakeSession(info, srv)
	f.mu.Lock()
	f.sessions = append(f.sessions, s)
	f.mu.Unlock()
	return s, nil
}

func (f *fixture) dials() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cfgs)
}

func (f *fixture) session(i int) *fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.sessions) {
		f.t.Fatalf("session %d not made (%d sessions)", i, len(f.sessions))
	}
	return f.sessions[i]
}

// request is one Process call with its link.
type request struct {
	up   *pipe.Writer
	down *pipe.Reader
	ob   *session.Outbound
	errc chan error
}

func (f *fixture) start(ctx context.Context, dest xnet.Destination) *request {
	ob := &session.Outbound{Target: dest, Tag: "vpn"}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	r := &request{up: upW, down: downR, ob: ob, errc: make(chan error, 1)}
	h, d := f.h, f.dialer
	go func() {
		r.errc <- h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d)
	}()
	return r
}

func (r *request) send(t *testing.T, b []byte) {
	t.Helper()
	if err := r.up.WriteMultiBuffer(buf.MergeBytes(nil, b)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func (r *request) recv(t *testing.T, n int) []byte {
	t.Helper()
	deadline := time.Now().Add(waitLong)
	var out []byte
	for len(out) < n {
		left := time.Until(deadline)
		if left <= 0 {
			t.Fatalf("received %d of %d bytes", len(out), n)
		}
		mb, err := r.down.ReadMultiBufferTimeout(left)
		if err != nil {
			select {
			case perr := <-r.errc:
				t.Fatalf("received %d of %d bytes: %v (Process: %v)", len(out), n, err, perr)
			default:
			}
			t.Fatalf("received %d of %d bytes: %v", len(out), n, err)
		}
		for _, b := range mb {
			out = append(out, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
	}
	return out
}

func (r *request) echo(t *testing.T, payload []byte) {
	t.Helper()
	r.send(t, payload)
	if got := r.recv(t, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d different bytes", len(payload), len(got))
	}
}

// wait returns Process's error, failing when it takes longer than d.
func (r *request) wait(t *testing.T, d time.Duration) error {
	t.Helper()
	select {
	case err := <-r.errc:
		return err
	case <-time.After(d):
		t.Fatalf("Process did not return within %v", d)
		return nil
	}
}

// end closes the request and waits for Process.
func (r *request) end(t *testing.T) error {
	t.Helper()
	common.Interrupt(r.up)
	common.Interrupt(r.down)
	return r.wait(t, waitLong)
}

func tcpDest(a netip.Addr, port uint16) xnet.Destination {
	return xnet.TCPDestination(xnet.IPAddress(a.AsSlice()), xnet.Port(port))
}

func udpDest(a netip.Addr, port uint16) xnet.Destination {
	return xnet.UDPDestination(xnet.IPAddress(a.AsSlice()), xnet.Port(port))
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// ---------------------------------------------------------------- tests

func TestParseOptions(t *testing.T) {
	cases := []struct {
		name string
		conf *Config
		want string // "" = valid
	}{
		{"valid", &Config{Ovpn: testOVPN}, ""},
		{"valid with credentials", &Config{Ovpn: testOVPN + "auth-user-pass\n", Username: "u", Password: "p"}, ""},
		{"valid mtu", &Config{Ovpn: testOVPN, Mtu: 1280}, ""},
		{"valid strategy", &Config{Ovpn: testOVPN, DomainStrategy: Config_FORCE_IP64}, ""},
		{"nil", nil, "no configuration"},
		{"empty", &Config{Ovpn: " \n"}, "empty"},
		{"no remote", &Config{Ovpn: "client\ndev tun\n"}, "no remote"},
		{"unsupported", &Config{Ovpn: testOVPN + "dev tap\n"}, "invalid ovpn"},
		{"mtu low", &Config{Ovpn: testOVPN, Mtu: MinMTU - 1}, "out of range"},
		{"mtu high", &Config{Ovpn: testOVPN, Mtu: MaxMTU + 1}, "out of range"},
		{"strategy", &Config{Ovpn: testOVPN, DomainStrategy: 99}, "unknown domain strategy"},
		{"password only", &Config{Ovpn: testOVPN, Password: "p"}, "without a username"},
		{"auth-user-pass", &Config{Ovpn: testOVPN + "auth-user-pass\n"}, "auth-user-pass"},
		{"bad ca", &Config{Ovpn: strings.Replace(testOVPN, testCA, badCA, 1)}, "unusable certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := tc.conf.ParseOptions()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if len(o.Remotes) != 1 || o.Remotes[0].Host != "192.0.2.10" {
					t.Fatalf("remotes %+v", o.Remotes)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one mentioning %q", err, tc.want)
			}
			if _, err := newHandler(tc.conf, policy.DefaultManager{}, &fakeDNS{}); err == nil {
				t.Fatal("newHandler accepted it")
			}
		})
	}
}

func TestTransportDestination(t *testing.T) {
	cases := []struct {
		network, address string
		want             xnet.Destination
		bad              bool
	}{
		{network: "udp", address: "10.0.0.1:1194", want: xnet.UDPDestination(xnet.ParseAddress("10.0.0.1"), 1194)},
		{network: "udp4", address: "vpn.example.com:1194", want: xnet.UDPDestination(xnet.DomainAddress("vpn.example.com"), 1194)},
		{network: "udp6", address: "[2001:db8::1]:53", want: xnet.UDPDestination(xnet.ParseAddress("2001:db8::1"), 53)},
		{network: "tcp", address: "vpn.example.com:443", want: xnet.TCPDestination(xnet.DomainAddress("vpn.example.com"), 443)},
		{network: "tcp4", address: "192.0.2.1:1", want: xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 1)},
		{network: "tcp6", address: "[::1]:65535", want: xnet.TCPDestination(xnet.ParseAddress("::1"), 65535)},
		{network: "sctp", address: "10.0.0.1:1194", bad: true},
		{network: "tcp-client", address: "10.0.0.1:1194", bad: true},
		{network: "udp", address: "10.0.0.1", bad: true},
		{network: "udp", address: ":1194", bad: true},
		{network: "udp", address: "h:0", bad: true},
		{network: "udp", address: "h:65536", bad: true},
		{network: "udp", address: "h:-1", bad: true},
		{network: "udp", address: "h:x", bad: true},
	}
	for _, tc := range cases {
		got, err := transportDestination(tc.network, tc.address)
		if tc.bad {
			if err == nil {
				t.Errorf("%s %q: no error, got %v", tc.network, tc.address, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %q: %v", tc.network, tc.address, err)
			continue
		}
		if got.Network != tc.want.Network || got.Port != tc.want.Port || got.Address.String() != tc.want.Address.String() ||
			got.Address.Family() != tc.want.Address.Family() {
			t.Errorf("%s %q: got %v, want %v", tc.network, tc.address, got, tc.want)
		}
	}
}

func FuzzTransportDestination(f *testing.F) {
	f.Add("udp", "10.0.0.1:1194")
	f.Add("tcp6", "[2001:db8::1]:443")
	f.Add("udp4", "vpn.example.com:1194")
	f.Add("tcp", "[::ffff:1.2.3.4%eth0]:1")
	f.Fuzz(func(t *testing.T, network, address string) {
		d, err := transportDestination(network, address)
		if err != nil {
			return
		}
		if d.Port == 0 || d.Address == nil || (d.Network != xnet.Network_UDP && d.Network != xnet.Network_TCP) {
			t.Fatalf("accepted %q %q as %v", network, address, d)
		}
		_ = d.String()
	})
}

func TestLookupInTunnel(t *testing.T) {
	d := &fakeDNS{answers: map[string][]net.IP{
		"both.test": {net.ParseIP("10.0.0.1").To4(), net.ParseIP("2001:db8::1")},
		"v4.test":   {net.ParseIP("10.0.0.2").To4()},
		"v6.test":   {net.ParseIP("2001:db8::2")},
	}}
	const v4, v6, both, fail = "4", "6", "46", ""
	cases := []struct {
		strategy   Config_DomainStrategy
		has4, has6 bool
		domain     string
		want       string // families of the answer
	}{
		{Config_FORCE_IP, true, true, "both.test", both},
		{Config_FORCE_IP, true, false, "both.test", v4},
		{Config_FORCE_IP, false, true, "both.test", v6},
		{Config_FORCE_IP, true, false, "v6.test", fail},
		{Config_FORCE_IP4, true, true, "both.test", v4},
		{Config_FORCE_IP4, false, true, "both.test", fail},
		{Config_FORCE_IP6, true, true, "both.test", v6},
		{Config_FORCE_IP6, true, true, "v4.test", fail},
		{Config_FORCE_IP46, true, true, "both.test", v4},
		{Config_FORCE_IP46, true, true, "v6.test", v6},
		{Config_FORCE_IP46, false, true, "both.test", v6},
		{Config_FORCE_IP64, true, true, "both.test", v6},
		{Config_FORCE_IP64, true, true, "v4.test", v4},
		{Config_FORCE_IP64, true, false, "v6.test", fail},
		{Config_FORCE_IP, true, true, "none.test", fail},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("%v/%v%v/%s", tc.strategy, tc.has4, tc.has6, tc.domain)
		ips, err := lookupInTunnel(d, &Config{DomainStrategy: tc.strategy}, tc.has4, tc.has6, tc.domain)
		if tc.want == fail {
			if err == nil {
				t.Errorf("%s: got %v, want an error", name, ips)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		fam := ""
		for _, ip := range ips {
			f := "6"
			if ip.To4() != nil {
				f = "4"
			}
			if !strings.Contains(fam, f) {
				fam += f
			}
		}
		if fam != tc.want {
			t.Errorf("%s: families %q (%v), want %q", name, fam, ips, tc.want)
		}
	}
}

// One session carries TCP over both families, UDP, a domain destination and
// a bulk transfer; the transport is dialled through Process's dialer.
func TestProcess(t *testing.T) {
	f := newFixture(t, &Config{Ovpn: testOVPN, Username: "alice", Password: "pw"})
	transportSeen := make(chan error, 1)
	f.hook = func(ctx context.Context, cfg client.Config) error {
		c, err := cfg.Dial(ctx, "udp", "192.0.2.10:1194")
		if err == nil {
			_ = c.Close()
		}
		transportSeen <- err
		return nil
	}

	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("hello over tcp"))
	r.echo(t, pattern(300<<10))
	if r.ob.Name != "ov" || r.ob.CanSpliceCopy != 3 {
		t.Errorf("outbound name %q splice %d", r.ob.Name, r.ob.CanSpliceCopy)
	}
	if err := <-transportSeen; err != nil {
		t.Fatalf("transport dial: %v", err)
	}

	r6 := f.start(context.Background(), tcpDest(srvV6, echoTCPPort))
	r6.echo(t, []byte("hello over tcp6"))

	ru := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	ru.echo(t, []byte("ping"))
	ru.echo(t, pattern(1200))

	rd := f.start(context.Background(), xnet.TCPDestination(xnet.DomainAddress("echo.test"), echoTCPPort))
	rd.echo(t, []byte("hello by name"))

	for _, req := range []*request{r, r6, ru, rd} {
		_ = req.end(t)
	}
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}

	f.mu.Lock()
	cfg := f.cfgs[0]
	f.mu.Unlock()
	if cfg.Username != "alice" || cfg.Password != "pw" || cfg.Logger == nil || cfg.Platform == "" || cfg.Options == nil {
		t.Errorf("client config: user %q logger %v platform %q options %v", cfg.Username, cfg.Logger != nil, cfg.Platform, cfg.Options != nil)
	}
	f.dialer.mu.Lock()
	defer f.dialer.mu.Unlock()
	if len(f.dialer.dests) != 1 {
		t.Fatalf("dialer saw %v", f.dialer.dests)
	}
	want := xnet.UDPDestination(xnet.ParseAddress("192.0.2.10"), 1194)
	if d := f.dialer.dests[0]; d != want {
		t.Errorf("transport destination %v, want %v", d, want)
	}
	obs := session.OutboundsFromContext(f.dialer.ctxs[0])
	if len(obs) != 1 || obs[0].Target != want || obs[0].Tag != "vpn" || obs[0] == r.ob {
		t.Errorf("transport dial context outbound %+v", obs)
	}
	if r.ob.Target != tcpDest(srvV4, echoTCPPort) || r.ob.Conn != nil {
		t.Errorf("the first request's outbound was changed: %+v", r.ob)
	}
}

func TestMissingFamily(t *testing.T) {
	f := newFixture(t, nil)
	f.info.IPv6 = netip.Prefix{}
	r := f.start(context.Background(), tcpDest(srvV6, echoTCPPort))
	err := r.wait(t, waitLong)
	if err == nil || !strings.Contains(err.Error(), "no IPv6 address") {
		t.Fatalf("Process: %v", err)
	}
	r = f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("v4 still works"))
	_ = r.end(t)
}

func TestNoTunnelAddress(t *testing.T) {
	f := newFixture(t, nil)
	f.info = client.TunnelInfo{MTU: 1500}
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	err := r.wait(t, waitLong)
	if err == nil || !strings.Contains(err.Error(), "no tunnel address") {
		t.Fatalf("Process: %v", err)
	}
	if n := f.session(0).closes.Load(); n != 1 {
		t.Fatalf("session closed %d times, want 1", n)
	}
}

// When the session dies, connections in flight fail at once and the next
// request builds a new session.
func TestSessionDeathRebuilds(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("first session"))

	f.session(0).fail(client.ErrPingTimeout)
	if err := r.wait(t, waitLong); err == nil {
		t.Fatal("Process ended without an error after the session died")
	}

	r2 := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r2.echo(t, []byte("second session"))
	if n := f.dials(); n != 2 {
		t.Fatalf("%d sessions dialled, want 2", n)
	}
	_ = r2.end(t)
}

// Requests that arrive during the handshake wait for it; there is one
// handshake.
func TestConcurrentRequestsShareHandshake(t *testing.T) {
	f := newFixture(t, nil)
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	f.hook = func(ctx context.Context, cfg client.Config) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	var reqs []*request
	for i := 0; i < 6; i++ {
		dest := tcpDest(srvV4, echoTCPPort)
		if i%2 == 1 {
			dest = udpDest(srvV4, echoUDPPort)
		}
		reqs = append(reqs, f.start(context.Background(), dest))
	}
	<-entered
	time.Sleep(50 * time.Millisecond)
	if n := f.dials(); n != 1 {
		t.Fatalf("%d handshakes in flight, want 1", n)
	}
	close(release)
	for i, r := range reqs {
		r.echo(t, []byte(fmt.Sprintf("request %d", i)))
	}
	for _, r := range reqs {
		_ = r.end(t)
	}
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}
}

// A request whose context ends while it waits for the handshake returns; the
// handshake goes on for the next request.
func TestWaitingRequestGivesUp(t *testing.T) {
	f := newFixture(t, nil)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	f.hook = func(ctx context.Context, cfg client.Config) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := f.start(ctx, tcpDest(srvV4, echoTCPPort))
	<-entered
	cancel()
	if err := r.wait(t, waitLong); err == nil || !goerrors.Is(err, context.Canceled) {
		t.Fatalf("Process: %v, want context.Canceled", err)
	}
	close(release)
	r2 := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r2.echo(t, []byte("after the first gave up"))
	_ = r2.end(t)
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}
}

// A failed handshake is retried by the first request after the back-off.
func TestHandshakeFailureThenRetry(t *testing.T) {
	f := newFixture(t, nil)
	clock := f.fakeClock()
	var calls atomic.Int32
	f.hook = func(ctx context.Context, cfg client.Config) error {
		if calls.Add(1) == 1 {
			return fmt.Errorf("openvpn: no remote worked: remote 192.0.2.10:1194/udp: %w", client.ErrHandshakeTimeout)
		}
		return nil
	}
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	err := r.wait(t, waitLong)
	if err == nil || !strings.Contains(err.Error(), "handshake timed out") {
		t.Fatalf("Process: %v", err)
	}
	clock.Advance(retryFirst)
	r2 := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r2.echo(t, []byte("second try"))
	_ = r2.end(t)
	if n := f.dials(); n != 2 {
		t.Fatalf("%d sessions dialled, want 2", n)
	}
}

func TestCloseDuringHandshake(t *testing.T) {
	f := newFixture(t, nil)
	entered := make(chan struct{}, 1)
	f.hook = func(ctx context.Context, cfg client.Config) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	<-entered
	done := make(chan struct{})
	go func() {
		_ = f.h.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitLong):
		t.Fatal("Close hung during the handshake")
	}
	if err := r.wait(t, waitLong); err == nil {
		t.Fatal("Process succeeded after Close")
	}
	if err := f.h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	r2 := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	if err := r2.wait(t, waitLong); !goerrors.Is(err, errClosed) {
		t.Fatalf("Process after Close: %v", err)
	}
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}
}

func TestCloseEndsSession(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("up"))
	f.h.mu.Lock()
	tun := f.h.tun
	f.h.mu.Unlock()

	if err := f.h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tun.finished:
	default:
		t.Fatal("Close returned before the tunnel was released")
	}
	if n := f.session(0).closes.Load(); n != 1 {
		t.Fatalf("session closed %d times, want 1", n)
	}
	if err := r.wait(t, waitLong); err == nil {
		t.Fatal("Process ended without an error after Close")
	}
	if err := f.h.Close(); err != nil {
		t.Fatal(err)
	}
	if n := f.session(0).closes.Load(); n != 1 {
		t.Fatalf("session closed %d times after a second Close, want 1", n)
	}
}

// A different dialer on a later request keeps the live session.
func TestDialerChangeKeepsSession(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("one"))
	f.dialer = &fakeDialer{}
	r2 := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r2.echo(t, []byte("two"))
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}
	_, _ = r.end(t), r2.end(t)
}

func TestTunnelMTU(t *testing.T) {
	cases := []struct {
		conf, session, want int
	}{
		{0, 1500, defaultMTU},
		{0, 1200, 1200},
		{0, 0, defaultMTU},
		{1300, 1500, 1300},
		{9000, 1500, 9000},
	}
	for _, tc := range cases {
		ctx, cancel := context.WithCancel(context.Background())
		s := newFakeSession(client.TunnelInfo{IPv4: cliV4, MTU: tc.session}, nil)
		tun, err := newTunnel(ctx, cancel, s, tc.conf)
		if err != nil {
			t.Fatal(err)
		}
		tun.start()
		if tun.mtu != tc.want {
			t.Errorf("conf %d session %d: mtu %d, want %d", tc.conf, tc.session, tun.mtu, tc.want)
		}
		if m, _ := tun.dev.MTU(); m != tc.want {
			t.Errorf("device MTU %d, want %d", m, tc.want)
		}
		tun.close()
		select {
		case <-tun.finished:
		default:
			t.Fatal("tunnel not released")
		}
		if ctx.Err() == nil {
			t.Fatal("the session context outlived the tunnel")
		}
	}
}

// The transport dial honours the session's dial context, and a connection
// that arrives after it gave up is closed. The dial itself runs on the
// session context, which the dial context's end does not cancel.
func TestDialFuncCancel(t *testing.T) {
	h, err := newHandler(&Config{Ovpn: testOVPN}, policy.DefaultManager{}, &fakeDNS{})
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDialer{release: make(chan struct{})}
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	dial := h.dialFunc(base, d)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := dial(ctx, "tcp", "192.0.2.1:443")
	if !goerrors.Is(err, context.DeadlineExceeded) || c != nil {
		t.Fatalf("dial: %v, %v", c, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("dial did not give up with its context")
	}
	close(d.release)
	deadline := time.Now().Add(waitLong)
	for {
		d.mu.Lock()
		n := len(d.conns)
		closed := n == 1 && d.conns[0].closed.Load()
		dctx := d.ctxs[0]
		d.mu.Unlock()
		if closed {
			if dctx.Err() != nil {
				t.Fatal("the transport was dialled with a context that ended")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late connection was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	d2 := &fakeDialer{err: goerrors.New("refused")}
	if _, err := h.dialFunc(base, d2)(context.Background(), "udp", "192.0.2.1:1194"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("dial error: %v", err)
	}
	if _, err := h.dialFunc(base, d2)(context.Background(), "udp", "192.0.2.1"); err == nil {
		t.Fatal("bad address dialled")
	}
}

func TestSessionLogger(t *testing.T) {
	l := sessionLogger{ctx: context.Background()}
	if got := l.line("openvpn: connecting to %s", []any{"x"}); got != "connecting to x" {
		t.Fatalf("line %q", got)
	}
	l.Debugf("openvpn: %d", 1)
	l.Infof("openvpn: %d", 2)
	l.Warnf("openvpn: %d", 3)
	if platform() == "" {
		t.Fatal("no platform")
	}
}
