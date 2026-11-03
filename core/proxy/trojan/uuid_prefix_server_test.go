package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

const prefixServerPassword = "00112233-4455-6677-8899-aabbccddeeff"

type prefixServerPolicy struct{}

func (prefixServerPolicy) Type() interface{}        { return policy.ManagerType() }
func (prefixServerPolicy) Start() error             { return nil }
func (prefixServerPolicy) Close() error             { return nil }
func (prefixServerPolicy) ForSystem() policy.System { return policy.System{} }
func (prefixServerPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Timeouts.Handshake = 2 * time.Second
	p.Timeouts.ConnectionIdle = 2 * time.Second
	p.Timeouts.UplinkOnly = 100 * time.Millisecond
	p.Timeouts.DownlinkOnly = 100 * time.Millisecond
	return p
}

type prefixDispatchRecord struct {
	destination xnet.Destination
	email       string
}

// The dispatcher loops actual server payloads back through a normal Xray pipe.
// Capturing the authenticated account also verifies that mixed-mode listeners
// do not accidentally route a request as another user with the same password.
type prefixEchoDispatcher struct {
	calls  atomic.Int32
	record chan prefixDispatchRecord
}

func (*prefixEchoDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*prefixEchoDispatcher) Start() error      { return nil }
func (*prefixEchoDispatcher) Close() error      { return nil }
func (*prefixEchoDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return fmt.Errorf("unexpected DispatchLink in Trojan test")
}
func (d *prefixEchoDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.calls.Add(1)
	user := session.InboundFromContext(ctx).User
	if user == nil {
		return nil, fmt.Errorf("dispatch before authentication")
	}
	d.record <- prefixDispatchRecord{destination: dest, email: user.Email}
	r, w := pipe.New(pipe.WithSizeLimit(64 * 1024))
	context.AfterFunc(ctx, func() { r.Interrupt(); w.Interrupt() })
	return &transport.Link{Reader: r, Writer: w}, nil
}

func prefixServerAccount(t *testing.T, custom bool) *MemoryAccount {
	t.Helper()
	a, err := (&Account{Password: prefixServerPassword, UuidHashPrefix: custom}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return a.(*MemoryAccount)
}

func prefixRuntimeServer(t *testing.T, modes ...bool) *Server {
	t.Helper()
	v := new(Validator)
	for _, custom := range modes {
		if err := v.Add(&protocol.MemoryUser{
			Email: fmt.Sprintf("mode-%t@example.test", custom), Account: prefixServerAccount(t, custom),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{policyManager: prefixServerPolicy{}, validator: v}
}

// Build the request independently of ConnWriter and uuidPrefixedKey, so the
// ordinary-client check remains a stock-protocol regression control.
func prefixIndependentRequest(custom, udp bool, payload []byte) []byte {
	h := sha256.Sum224([]byte(prefixServerPassword))
	key := make([]byte, 56)
	hex.Encode(key, h[:])
	if custom {
		u, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
		copy(key[:16], u)
	}
	request := append(key, '\r', '\n')
	command := byte(1)
	if udp {
		command = 3
	}
	request = append(request, command)
	// Destination 127.0.0.1:23456. This test never dials the destination.
	address := []byte{1, 127, 0, 0, 1, 0x5b, 0xa0}
	request = append(request, address...)
	request = append(request, '\r', '\n')
	if udp {
		request = append(request, address...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
		request = append(request, length[:]...)
		request = append(request, '\r', '\n')
	}
	return append(request, payload...)
}

func runPrefixRuntimeRequest(t *testing.T, s *Server, custom, udp, accepted bool, mutate func([]byte)) {
	t.Helper()
	client, server := stdnet.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	d := &prefixEchoDispatcher{record: make(chan prefixDispatchRecord, 1)}
	result := make(chan error, 1)
	go func() {
		defer server.Close()
		result <- s.Process(ctx, xnet.Network_TCP, server, d)
	}()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("native-Trojan\x00TCP/UDP\r\npayload")
	request := prefixIndependentRequest(custom, udp, payload)
	if mutate != nil {
		mutate(request)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatalf("writing complete request: %v", err)
	}
	if accepted {
		if udp {
			mb, err := (&PacketReader{Reader: client}).ReadMultiBuffer()
			if err != nil {
				t.Fatalf("reading UDP echo: %v", err)
			}
			defer buf.ReleaseMulti(mb)
			if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) || mb[0].UDP == nil || mb[0].UDP.Port != 23456 {
				t.Fatal("UDP payload or destination changed")
			}
		} else {
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatalf("reading TCP echo: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("TCP payload changed")
			}
		}
		select {
		case record := <-d.record:
			wantNetwork := xnet.Network_TCP
			if udp {
				wantNetwork = xnet.Network_UDP
			}
			if record.email != fmt.Sprintf("mode-%t@example.test", custom) || record.destination.Network != wantNetwork || record.destination.Port != 23456 || !record.destination.Address.IP().Equal(stdnet.IPv4(127, 0, 0, 1)) {
				t.Fatalf("wrong authenticated route: %+v", record)
			}
		case <-ctx.Done():
			t.Fatal("accepted request never reached the dispatcher")
		}
	} else {
		var one [1]byte
		if n, err := client.Read(one[:]); n != 0 || err == nil {
			t.Fatal("rejected credentials received a response")
		}
	}
	_ = client.Close()
	select {
	case err := <-result:
		if !accepted && err == nil {
			t.Fatal("bad authentication returned success")
		}
	case <-ctx.Done():
		t.Fatal("server request failed to terminate")
	}
	if accepted && d.calls.Load() != 1 {
		t.Fatalf("accepted request dispatched %d times", d.calls.Load())
	}
	if !accepted && d.calls.Load() != 0 {
		t.Fatal("rejected request reached routing")
	}
}

func TestUUIDPrefixServerNativeTCPAndUDP(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("custom=%t/udp=%t", custom, udp), func(t *testing.T) {
				runPrefixRuntimeRequest(t, prefixRuntimeServer(t, custom), custom, udp, true, nil)
			})
		}
	}
}

func TestUUIDPrefixServerMixedUsers(t *testing.T) {
	s := prefixRuntimeServer(t, false, true)
	for _, udp := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("custom=%t/udp=%t", custom, udp), func(t *testing.T) {
				runPrefixRuntimeRequest(t, s, custom, udp, true, nil)
			})
		}
	}
	if err := s.RemoveUser(context.Background(), "mode-true@example.test"); err != nil {
		t.Fatal(err)
	}
	runPrefixRuntimeRequest(t, s, false, false, true, nil)
	runPrefixRuntimeRequest(t, s, true, false, false, nil)
}

func TestUUIDPrefixServerRejectsWrongAuthentication(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("cross-mode/custom=%t/udp=%t", custom, udp), func(t *testing.T) {
				runPrefixRuntimeRequest(t, prefixRuntimeServer(t, !custom), custom, udp, false, nil)
			})
			t.Run(fmt.Sprintf("wrong-key/custom=%t/udp=%t", custom, udp), func(t *testing.T) {
				runPrefixRuntimeRequest(t, prefixRuntimeServer(t, custom), custom, udp, false, func(b []byte) { b[20] ^= 1 })
			})
		}
	}
}
