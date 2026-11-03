package client

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// nullConn swallows writes and blocks reads until closed.
type nullConn struct {
	once   sync.Once
	closed chan struct{}
}

func newNullConn() *nullConn { return &nullConn{closed: make(chan struct{})} }

func (n *nullConn) Read([]byte) (int, error)         { <-n.closed; return 0, net.ErrClosed }
func (n *nullConn) Write(b []byte) (int, error)      { return len(b), nil }
func (n *nullConn) Close() error                     { n.once.Do(func() { close(n.closed) }); return nil }
func (n *nullConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (n *nullConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (n *nullConn) SetDeadline(time.Time) error      { return nil }
func (n *nullConn) SetReadDeadline(time.Time) error  { return nil }
func (n *nullConn) SetWriteDeadline(time.Time) error { return nil }

var fuzzServerSID = wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8}

func fuzzDialer(t testing.TB) *dialer {
	o := parseOpts(t, ovpnText(t, "remote 127.0.0.1 1194 udp\n"))
	d, err := newDialer(Config{Options: o, Dial: netDial})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// fuzzKey2 is a fixed key block shared by the fuzz client and the seeds.
func fuzzKey2() *handshake.Key2 {
	var k handshake.Key2
	for i := range k {
		for j := range k[i].Cipher {
			k[i].Cipher[j] = byte(i*64 + j)
			k[i].HMAC[j] = byte(255 - i*64 - j)
		}
	}
	return &k
}

// fuzzClient is a session in the "up" state with key 0 installed, without
// goroutines; the fuzz body drives dispatch and the control loop's handlers
// directly.
func fuzzClient(t testing.TB, d *dialer, up bool) *Client {
	c, err := newClient(d, options.Remote{Host: "127.0.0.1", Port: 1194, Network: "udp"}, newNullConn())
	if err != nil {
		t.Fatal(err)
	}
	s := &c.loop
	s.haveServerSID = true
	s.serverSID = fuzzServerSID
	s.primary.peerReset = true
	s.primary.exchanged = true
	s.primary.server = &handshake.ServerMessage{}
	s.primary.established = time.Now()
	if up {
		s.up = true
		s.cipher, s.digest, s.keyDerivation = "AES-256-GCM", "SHA1", "prf"
		k2 := fuzzKey2()
		dk, err := datachan.NewKeyState(0, s.cipher, s.digest, k2.ClientSend(), k2.ClientRecv())
		if err != nil {
			t.Fatal(err)
		}
		ch := datachan.New(datachan.Options{PeerID: 3})
		ch.SetPrimary(dk)
		c.data.Store(ch)
	} else {
		s.pushing = true
	}
	return c
}

func stopFuzzClient(c *Client) {
	c.fail(ErrClosed)
	c.closeKeys()
	c.wg.Wait()
}

func controlSeed(op wire.Opcode, key uint8, acks []wire.PacketID, id wire.PacketID, payload string) []byte {
	return wire.Marshal(&wire.ControlPacket{Opcode: op, KeyID: key, SessionID: fuzzServerSID, Acks: acks, PacketID: id, Payload: []byte(payload)})
}

// FuzzClientInput feeds arbitrary link packets to a running session: none
// may panic, whatever they claim to be.
func FuzzClientInput(f *testing.F) {
	d := fuzzDialer(f)
	k2 := fuzzKey2()
	srvKey, err := datachan.NewKeyState(0, "AES-256-GCM", "SHA1", k2.ServerSend(), k2.ServerRecv())
	if err != nil {
		f.Fatal(err)
	}
	srvCh := datachan.New(datachan.Options{PeerID: 3})
	srvCh.SetPrimary(srvKey)
	data, _ := srvCh.Seal(nil, []byte{0x45, 0, 0, 20, 1, 2, 3, 4})
	ping, _ := srvCh.SealPing(nil)
	occ, _ := srvCh.SealOCC(nil, datachan.OCCExit)

	frame := func(pkts ...[]byte) []byte {
		var b []byte
		for _, p := range pkts {
			b = append(b, byte(len(p)-1))
			b = append(b, p...)
		}
		return b
	}
	f.Add(frame(data, ping))
	f.Add(frame(occ))
	f.Add(frame(controlSeed(wire.ControlSoftResetV1, 1, nil, 0, "")))
	f.Add(frame(controlSeed(wire.ControlSoftResetV1, 1, nil, 0, ""), controlSeed(wire.ControlV1, 1, nil, 1, "\x16\x03\x03\x00\x05hello")))
	f.Add(frame(controlSeed(wire.AckV1, 0, []wire.PacketID{0, 1}, 0, "")))
	f.Add(frame(controlSeed(wire.ControlV1, 0, nil, 1, "PUSH_REPLY")))
	f.Add(frame(controlSeed(wire.ControlHardResetServerV2, 0, nil, 0, "")))
	f.Add([]byte{0, 0x48})

	f.Fuzz(func(t *testing.T, in []byte) {
		c := fuzzClient(t, d, true)
		defer stopFuzzClient(c)
		now := time.Now()
		for len(in) > 0 {
			n := int(in[0]) + 1
			in = in[1:]
			n = min(n, len(in))
			pkt := in[:n]
			in = in[n:]
			if len(pkt) == 0 {
				continue
			}
			c.dispatch(pkt)
		drain:
			for {
				select {
				case p := <-c.ctlIn:
					if err := c.handleControlPacket(p, now); err != nil {
						return
					}
				default:
					break drain
				}
			}
			c.flush(now)
			if c.isDone() {
				return
			}
		}
	})
}

// FuzzControlMessage feeds arbitrary control messages to a session that
// waits for its PUSH_REPLY and to one that is up.
func FuzzControlMessage(f *testing.F) {
	d := fuzzDialer(f)
	for _, s := range []string{
		"PUSH_REPLY,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM",
		"PUSH_REPLY,cipher BOGUS",
		"PUSH_REPLY,key-derivation tls-ekm",
		"PUSH_REPLY,route 10.0.0.0 255.0.0.0,push-continuation 2",
		"PUSH_REPLY,auth-token abc,auth-token-user Ym9i",
		"PUSH_REPLY,cipher AES-128-CBC,auth NONE",
		"AUTH_FAILED,reason\xff\x00",
		"AUTH_PENDING,timeout 30",
		"INFO_PRE,WEB_AUTH::https://example.invalid",
		"RESTART,[!]bye",
		"HALT",
		"EXIT",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		for _, up := range []bool{false, true} {
			c := fuzzClient(t, d, up)
			_ = c.handleControlMessage(msg, time.Now())
			_ = c.handleControlMessage(msg, time.Now())
			stopFuzzClient(c)
		}
	})
}

// FuzzSplitControlMessages checks the splitter's invariants.
func FuzzSplitControlMessages(f *testing.F) {
	f.Add([]byte("PUSH_REQUEST\x00"))
	f.Add([]byte("a\x00\x00b\x00c"))
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, rest := splitControlMessages(b)
		var joined []byte
		for _, m := range msgs {
			if m == "" || bytes.IndexByte([]byte(m), 0) >= 0 {
				t.Fatalf("bad message %q", m)
			}
			joined = append(joined, m...)
		}
		if bytes.IndexByte(rest, 0) >= 0 {
			t.Fatalf("rest %q holds a NUL", rest)
		}
		joined = append(joined, rest...)
		if !bytes.Equal(joined, bytes.ReplaceAll(b, []byte{0}, nil)) {
			t.Fatalf("split lost bytes")
		}
	})
}
