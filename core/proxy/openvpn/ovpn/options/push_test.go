package options

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// exported copies the exported fields of p, so that tests compare only
// what callers see.
func exported(p *Pushed) Pushed {
	return Pushed{
		IPv4: p.IPv4, PeerV4: p.PeerV4, GatewayV4: p.GatewayV4, IPv6: p.IPv6, GatewayV6: p.GatewayV6,
		Routes: p.Routes, DNS: p.DNS, Topology: p.Topology,
		Cipher: p.Cipher, Auth: p.Auth, PeerID: p.PeerID, KeyDerivation: p.KeyDerivation, ProtocolFlags: p.ProtocolFlags,
		Ping: p.Ping, PingRestart: p.PingRestart, TunMTU: p.TunMTU,
		Compression: p.Compression, CompressionSet: p.CompressionSet,
		AuthToken: p.AuthToken, AuthTokenUser: p.AuthTokenUser, ExplicitExitNotify: p.ExplicitExitNotify,
	}
}

func TestNewPushed(t *testing.T) {
	p := NewPushed()
	if p.PeerID != wire.NoPeerID {
		t.Errorf("PeerID = %#x", p.PeerID)
	}
	more, err := p.ApplyPushReply("PUSH_REPLY", nil)
	if err != nil || more {
		t.Fatalf("empty PUSH_REPLY: %v %v", more, err)
	}
	if got := exported(p); !reflect.DeepEqual(got, Pushed{PeerID: wire.NoPeerID}) {
		t.Errorf("empty PUSH_REPLY changed %+v", got)
	}
}

type pushCase struct {
	name    string
	msgs    []string
	filters []PullFilter
	// more is the result for each message.
	more    []bool
	want    func(p *Pushed)
	ignored []string
}

var pushCases = []pushCase{
	{
		name: "openvpn 2.6 subnet with IPv6",
		msgs: []string{"PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60," +
			"ifconfig 10.8.0.2 255.255.255.0,ifconfig-ipv6 fd00::1000/64 fd00::1,peer-id 0,cipher AES-256-GCM," +
			"key-derivation tls-ekm,protocol-flags cc-exit tls-ekm dyn-tls-crypt,dhcp-option DNS 10.8.0.1," +
			"dns server 0 address 10.8.0.1 [fd00::1]:53,route 10.9.0.0 255.255.255.0,auth-token SESS_ID_AT_0123456789abcdef," +
			"auth-token-user dXNlcg==,tun-mtu 1500,redirect-gateway def1,block-ipv6,explicit-exit-notify 1"},
		want: func(p *Pushed) {
			p.GatewayV4 = addr("10.8.0.1")
			p.Topology = "subnet"
			p.Ping, p.PingRestart = 10*time.Second, 60*time.Second
			p.IPv4 = pfx("10.8.0.2/24")
			p.IPv6, p.GatewayV6 = pfx("fd00::1000/64"), addr("fd00::1")
			p.PeerID = 0
			p.Cipher = "AES-256-GCM"
			p.KeyDerivation = "tls-ekm"
			p.ProtocolFlags = []string{"cc-exit", "tls-ekm", "dyn-tls-crypt"}
			p.DNS = []netip.Addr{addr("10.8.0.1"), addr("fd00::1")}
			p.Routes = []netip.Prefix{pfx("10.9.0.0/24")}
			p.AuthToken = "SESS_ID_AT_0123456789abcdef"
			p.AuthTokenUser = "user"
			p.TunMTU = 1500
			p.ExplicitExitNotify = 1
		},
		ignored: []string{"redirect-gateway", "block-ipv6"},
	},
	{
		name: "net30",
		msgs: []string{"PUSH_REPLY,route 10.8.0.1,topology net30,ping 10,ping-restart 120,ifconfig 10.8.0.6 10.8.0.5,peer-id 1,cipher aes-256-cbc,auth sha1\x00"},
		want: func(p *Pushed) {
			p.Routes = []netip.Prefix{pfx("10.8.0.1/32")}
			p.Topology = "net30"
			p.Ping, p.PingRestart = 10*time.Second, 120*time.Second
			p.IPv4, p.PeerV4 = pfx("10.8.0.6/32"), addr("10.8.0.5")
			p.PeerID = 1
			p.Cipher, p.Auth = "AES-256-CBC", "SHA1"
		},
	},
	{
		name: "p2p without a topology",
		msgs: []string{"PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5"},
		want: func(p *Pushed) { p.IPv4, p.PeerV4 = pfx("10.8.0.6/32"), addr("10.8.0.5") },
	},
	{
		name: "netmask without a topology",
		msgs: []string{"PUSH_REPLY,ifconfig 10.8.0.2 255.255.0.0"},
		want: func(p *Pushed) { p.IPv4 = pfx("10.8.0.2/16") },
	},
	{
		name: "topology after ifconfig in the same message",
		msgs: []string{"PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,topology p2p,ifconfig 10.8.1.2 255.255.255.128,topology subnet"},
		want: func(p *Pushed) {
			p.IPv4 = pfx("10.8.1.2/25")
			p.Topology = "subnet"
		},
	},
	{
		name: "topology from an earlier message, ifconfig 255.255.255.255",
		msgs: []string{"PUSH_REPLY,topology subnet,push-continuation 2", "PUSH_REPLY,ifconfig 10.8.0.9 255.255.255.255,push-continuation 1"},
		more: []bool{true, false},
		want: func(p *Pushed) {
			p.Topology = "subnet"
			p.IPv4 = pfx("10.8.0.9/32")
		},
	},
	{
		name: "continuation accumulates routes and DNS",
		msgs: []string{
			"PUSH_REPLY,route 10.1.0.0 255.255.0.0,dhcp-option DNS 1.1.1.1,push-continuation 2",
			"PUSH_REPLY,route 10.2.0.0 255.255.0.0 10.8.0.1 100,route-ipv6 2001:db8:1::/48,dhcp-option DNS 1.1.1.1,push-continuation 2",
			"PUSH_REPLY,route 10.3.0.0 255.255.0.0,route-ipv6 2001:db8:2::1/64 fd00::1,dhcp-option DNS6 2606:4700::1111,ping 5,push-continuation 1",
		},
		more: []bool{true, true, false},
		want: func(p *Pushed) {
			p.Routes = []netip.Prefix{pfx("10.1.0.0/16"), pfx("10.2.0.0/16"), pfx("2001:db8:1::/48"), pfx("10.3.0.0/16"), pfx("2001:db8:2::/64")}
			p.DNS = []netip.Addr{addr("1.1.1.1"), addr("2606:4700::1111")}
			p.Ping = 5 * time.Second
		},
	},
	{
		name: "later message overrides scalars",
		msgs: []string{"PUSH_REPLY,ping 10,cipher AES-128-GCM,peer-id 3,push-continuation 2", "PUSH_REPLY,ping 20,cipher AES-256-GCM,peer-id 16777214"},
		more: []bool{true, false},
		want: func(p *Pushed) {
			p.Ping = 20 * time.Second
			p.Cipher = "AES-256-GCM"
			p.PeerID = 0xFFFFFE
		},
	},
	{
		name: "dns forms and priorities",
		msgs: []string{"PUSH_REPLY,dhcp-option DNS 1.1.1.1,dhcp-option DNS6 2606:4700::1111,dhcp-option DOMAIN \"corp example\"," +
			"dns server 1 address 9.9.9.9,dns server 0 address 8.8.8.8:53 [2001:4860:4860::8888]:53 [2001::1] bogus,dns server 0 resolve-domains corp," +
			"dns server -2 address 1.1.1.1 fe80::1%eth0,dns search-domains corp.example,dns server 5 address nothing-valid"},
		want: func(p *Pushed) {
			p.DNS = []netip.Addr{addr("1.1.1.1"), addr("fe80::1"), addr("8.8.8.8"), addr("2001:4860:4860::8888"), addr("2001::1"), addr("9.9.9.9"), addr("2606:4700::1111")}
		},
		ignored: []string{"dhcp-option", "dns"},
	},
	{
		name: "protocol-flags alone selects tls-ekm",
		msgs: []string{"PUSH_REPLY,protocol-flags cc-exit tls-ekm,protocol-flags tls-ekm aead-epoch"},
		want: func(p *Pushed) {
			p.KeyDerivation = "tls-ekm"
			p.ProtocolFlags = []string{"cc-exit", "tls-ekm", "aead-epoch"}
		},
	},
	{
		name: "ifconfig-ipv6 forms",
		msgs: []string{"PUSH_REPLY,ifconfig-ipv6 2001:db8::5,route-gateway dhcp,route-gateway 300.1.1.1,keepalive 10 60"},
		want: func(p *Pushed) {
			p.IPv6 = pfx("2001:db8::5/64")
			p.Ping, p.PingRestart = 10*time.Second, 60*time.Second
		},
		ignored: []string{"route-gateway"},
	},
	{
		name: "spaces, empty options and quoted arguments",
		msgs: []string{"  PUSH_REPLY,, ping 7 ,auth-token \"tok en\",route vpn_gateway,route 10.0.0.0 255.0.255.0,auth-token-user !!!,explicit-exit-notify\x00"},
		want: func(p *Pushed) {
			p.Ping = 7 * time.Second
			p.AuthToken = "tok en"
			p.ExplicitExitNotify = 1
		},
		ignored: []string{"route", "auth-token-user"},
	},
	{
		name: "pull filters",
		msgs: []string{"PUSH_REPLY,route 10.1.0.0 255.255.0.0,route 192.168.0.0 255.255.0.0,dhcp-option DNS 10.8.0.1,ping 10,ping-restart 60"},
		filters: []PullFilter{
			{"accept", "route 10."},
			{"ignore", "route "},
			{"ignore", "dhcp-option"},
			{"reject", "dhcp-option"}, // never reached
			{"ignore", "ping-restart"},
		},
		want: func(p *Pushed) {
			p.Routes = []netip.Prefix{pfx("10.1.0.0/16")}
			p.Ping = 10 * time.Second
		},
		ignored: []string{"route", "dhcp-option", "ping-restart"},
	},
	{
		name:    "ignore filter on an option that would fail",
		msgs:    []string{"PUSH_REPLY,ifconfig garbage,ping 3"},
		filters: []PullFilter{{"ignore", "ifconfig"}},
		want:    func(p *Pushed) { p.Ping = 3 * time.Second },
	},
}

func TestApplyPushReply(t *testing.T) {
	for _, tc := range pushCases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPushed()
			for i, msg := range tc.msgs {
				more, err := p.ApplyPushReply(msg, tc.filters)
				if err != nil {
					t.Fatalf("message %d: %v", i, err)
				}
				wantMore := false
				if tc.more != nil {
					wantMore = tc.more[i]
				}
				if more != wantMore {
					t.Errorf("message %d: more = %v", i, more)
				}
			}
			want := Pushed{PeerID: wire.NoPeerID}
			tc.want(&want)
			if got := exported(p); !reflect.DeepEqual(got, want) {
				t.Errorf("mismatch\n got: %+v\nwant: %+v", got, want)
			}
			for _, n := range tc.ignored {
				if !slices.Contains(p.Ignored, n) {
					t.Errorf("Ignored %q does not list %q", p.Ignored, n)
				}
			}
		})
	}
}

func TestApplyPushReplyErrors(t *testing.T) {
	cases := []struct {
		name     string
		msg      string
		filters  []PullFilter
		contains string
	}{
		{"not a push reply", "AUTH_FAILED", nil, "not a PUSH_REPLY"},
		{"glued prefix", "PUSH_REPLYX,ping 1", nil, "not a PUSH_REPLY"},
		{"ifconfig one arg", "PUSH_REPLY,ifconfig 10.8.0.2", nil, "ifconfig"},
		{"ifconfig v6", "PUSH_REPLY,ifconfig fd00::2 255.255.255.0", nil, "bad IPv4"},
		{"ifconfig garbage", "PUSH_REPLY,ifconfig a b", nil, "bad IPv4"},
		{"subnet without netmask", "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 10.8.0.1", nil, "not a netmask"},
		{"ifconfig-ipv6 v4", "PUSH_REPLY,ifconfig-ipv6 10.0.0.1/24", nil, "bad IPv6"},
		{"ifconfig-ipv6 bits", "PUSH_REPLY,ifconfig-ipv6 fd00::1/129", nil, "prefix length"},
		{"ifconfig-ipv6 gateway", "PUSH_REPLY,ifconfig-ipv6 fd00::1/64 10.0.0.1", nil, "gateway"},
		{"peer-id too big", "PUSH_REPLY,peer-id 16777216", nil, "bad peer id"},
		{"peer-id negative", "PUSH_REPLY,peer-id -1", nil, "bad peer id"},
		{"key-derivation", "PUSH_REPLY,key-derivation prf-v2", nil, "unsupported method"},
		{"topology", "PUSH_REPLY,topology star", nil, "unknown topology"},
		{"tun-mtu", "PUSH_REPLY,tun-mtu 9999999", nil, "bad MTU"},
		{"ping", "PUSH_REPLY,ping x", nil, "bad number of seconds"},
		{"missing cipher", "PUSH_REPLY,cipher", nil, "missing argument"},
		{"empty cipher", "PUSH_REPLY,cipher \"\"", nil, "empty name"},
		{"unclosed quote", "PUSH_REPLY,auth-token \"abc", nil, "no closing double quote"},
		{"reject filter", "PUSH_REPLY,ping 1,redirect-gateway def1", []PullFilter{{"reject", "redirect-gateway"}}, "rejected by pull-filter"},
		{"explicit-exit-notify", "PUSH_REPLY,explicit-exit-notify -1", nil, "bad count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPushed().ApplyPushReply(tc.msg, tc.filters)
			if err == nil {
				t.Fatal("succeeded")
			}
			if !strings.Contains(err.Error(), tc.contains) || !strings.HasPrefix(err.Error(), "options: ") {
				t.Errorf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

// TestPushErrorsHideToken checks that a rejected or failing message does
// not put the auth token into the error.
func TestPushErrorsHideToken(t *testing.T) {
	for _, msg := range []string{
		"PUSH_REPLY,auth-token SECRET_TOKEN_VALUE,ifconfig x y",
		"PUSH_REPLY,auth-token SECRET_TOKEN_VALUE",
	} {
		_, err := NewPushed().ApplyPushReply(msg, []PullFilter{{"reject", "auth-token"}, {"reject", "ifconfig"}})
		if err == nil || strings.Contains(err.Error(), "SECRET_TOKEN_VALUE") {
			t.Errorf("%q: %v", msg, err)
		}
	}
}

func FuzzApplyPushReply(f *testing.F) {
	for _, tc := range pushCases {
		for _, m := range tc.msgs {
			f.Add(m)
		}
	}
	f.Add("PUSH_REPLY,ifconfig 10.0.0.1 0.0.0.0,topology subnet")
	f.Add("PUSH_REPLY,dns server 127 address [::1]:53 1.2.3.4:5353")
	if compressReady() {
		for _, s := range compressSeeds {
			f.Add(s)
		}
	}
	filters := []PullFilter{{"ignore", "route 192."}, {"reject", "setenv"}, {"accept", ""}}
	f.Fuzz(func(t *testing.T, msg string) {
		p := NewPushed()
		for i := 0; i < 2; i++ { // twice, as continuations do
			if _, err := p.ApplyPushReply(msg, filters); err != nil {
				return
			}
		}
		if p.PeerID > wire.NoPeerID {
			t.Fatalf("peer id %#x", p.PeerID)
		}
		if p.IPv4.IsValid() && !p.IPv4.Addr().Is4() {
			t.Fatalf("IPv4 %v", p.IPv4)
		}
		if p.IPv6.IsValid() && !p.IPv6.Addr().Is6() {
			t.Fatalf("IPv6 %v", p.IPv6)
		}
		seen := map[netip.Addr]bool{}
		for _, a := range p.DNS {
			if seen[a] || !a.IsValid() {
				t.Fatalf("DNS %v", p.DNS)
			}
			seen[a] = true
		}
	})
}
