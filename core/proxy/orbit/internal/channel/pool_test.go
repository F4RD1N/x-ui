package channel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

type fakePeer struct {
	user    protocol.UserInfo
	id      [16]byte
	mu      sync.Mutex
	conns   []net.Conn
	opens   int
	openErr error
	done    chan struct{}
	once    sync.Once
	udp     chan protocol.UDPEnvelope
	app     chan protocol.AppMessage
	sentUDP chan protocol.UDPEnvelope
	sentApp chan protocol.AppMessage
}

func fake() *fakePeer {
	return &fakePeer{user: protocol.UserInfo{UID: "owned"}, id: [16]byte{1}, done: make(chan struct{}), udp: make(chan protocol.UDPEnvelope, 512), app: make(chan protocol.AppMessage, 128), sentUDP: make(chan protocol.UDPEnvelope, 1), sentApp: make(chan protocol.AppMessage, 1)}
}
func (f *fakePeer) Open(ctx context.Context, h string, p uint16) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return nil, f.openErr
	}
	a, b := net.Pipe()
	f.conns = append(f.conns, a, b)
	f.opens++
	return a, nil
}
func (f *fakePeer) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	select {
	case f.sentUDP <- u:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fakePeer) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	select {
	case u := <-f.udp:
		return u, nil
	case <-f.done:
		return protocol.UDPEnvelope{}, io.EOF
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	}
}
func (f *fakePeer) SendApp(ctx context.Context, a protocol.AppMessage) error {
	select {
	case f.sentApp <- a:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fakePeer) ReceiveApp(ctx context.Context) (protocol.AppMessage, error) {
	select {
	case a := <-f.app:
		return a, nil
	case <-f.done:
		return protocol.AppMessage{}, io.EOF
	case <-ctx.Done():
		return protocol.AppMessage{}, ctx.Err()
	}
}
func (f *fakePeer) User() protocol.UserInfo { return f.user }
func (f *fakePeer) ChannelID() [16]byte     { return f.id }
func (f *fakePeer) Done() <-chan struct{}   { return f.done }
func (f *fakePeer) Err() error              { return io.EOF }
func (f *fakePeer) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.conns {
			c.Close()
		}
	})
	return nil
}
func (f *fakePeer) RouteMetadata() []byte { return []byte("owned-route") }
func testPool(t *testing.T) (*Pool, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	p := New(ctx, fake().user, fake().id)
	t.Cleanup(func() { p.Close(); cancel() })
	return p, ctx
}

func TestNativeLeastAttachedSelectionAndAffinity(t *testing.T) {
	raw, err := os.ReadFile("testdata/affinity.json")
	if err != nil {
		t.Fatal(err)
	}
	var gold struct {
		Cases []struct {
			Loads    []int
			Selected *int
		}
	}
	if err = json.Unmarshal(raw, &gold); err != nil {
		t.Fatal(err)
	}
	for _, tc := range gold.Cases {
		if tc.Selected == nil {
			continue
		}
		t.Run(string(rune('a'+len(tc.Loads))), func(t *testing.T) {
			p, ctx := testPool(t)
			peers := make([]*fakePeer, len(tc.Loads))
			for i, load := range tc.Loads {
				peers[i] = fake()
				if err = p.AddTCP(peers[i]); err != nil {
					t.Fatal(err)
				}
				p.members[i].active = load
			}
			p.Seal()
			conn, err := p.Open(ctx, "owned.test", 80)
			if *tc.Selected < 0 {
				if err == nil {
					t.Fatal("empty pool accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, peer := range peers {
				if (peer.opens == 1) != (i == *tc.Selected) {
					t.Fatal("selection differs from original", i, *tc.Selected)
				}
			}
			if err = conn.Close(); err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			_, _, counts := p.Counts()
			if !reflect.DeepEqual(counts, tc.Loads) {
				t.Fatal("flow count not released exactly once", counts, tc.Loads)
			}
		})
	}
}
func TestConcurrentLeastLoadedAndFailureRelease(t *testing.T) {
	p, ctx := testPool(t)
	for i := 0; i < 4; i++ {
		p.AddTCP(fake())
	}
	p.Seal()
	const n = 64
	conns := make(chan net.Conn, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := p.Open(ctx, "owned.test", 443)
			if e != nil {
				t.Error(e)
				return
			}
			conns <- c
		}()
	}
	wg.Wait()
	close(conns)
	tcp, quic, counts := p.Counts()
	if tcp != 4 || quic != 0 || !reflect.DeepEqual(counts, []int{16, 16, 16, 16}) {
		t.Fatal(tcp, quic, counts)
	}
	for c := range conns {
		_ = c.Close()
	}
	f := p.members[0].peer.(*fakePeer)
	f.openErr = io.ErrUnexpectedEOF
	if _, err := p.Open(ctx, "owned.test", 80); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	_, _, counts = p.Counts()
	if !reflect.DeepEqual(counts, []int{0, 0, 0, 0}) {
		t.Fatal(counts)
	}
}
func TestQUICPreferenceAndFallback(t *testing.T) {
	p, ctx := testPool(t)
	tcp, q := fake(), fake()
	p.AddTCP(tcp)
	p.AddQUIC(q)
	p.Seal()
	c, err := p.Open(ctx, "owned.test", 443)
	if err != nil || q.opens != 1 || tcp.opens != 0 {
		t.Fatal("QUIC preference", err)
	}
	_ = c.Close()
	_ = q.Close()
	c, err = p.Open(ctx, "owned.test", 443)
	if err != nil || tcp.opens != 1 {
		t.Fatal("TCP fallback", err)
	}
	_ = c.Close()
	_ = tcp.Close()
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatal("pool did not close")
	}
	if p.Err() == nil {
		t.Fatal("missing terminal error")
	}
}
func TestInitialDialWaitAndValidation(t *testing.T) {
	p, ctx := testPool(t)
	done := make(chan error, 1)
	go func() {
		c, err := p.Open(ctx, "owned.test", 443)
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	f := fake()
	if err := p.AddTCP(f); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wrong := fake()
	wrong.user.Token = "wrong"
	if !errors.Is(p.AddTCP(wrong), ErrIdentity) {
		t.Fatal("identity mismatch accepted")
	}
	wrong.user = f.user
	wrong.id[0] = 2
	if !errors.Is(p.AddTCP(wrong), ErrIdentity) {
		t.Fatal("channel mismatch accepted")
	}
	if !errors.Is(p.AddTCP(nil), ErrIdentity) {
		t.Fatal("nil peer")
	}
	q := fake()
	if err := p.AddQUIC(q); err != nil {
		t.Fatal(err)
	}
	if err := p.AddQUIC(fake()); err == nil {
		t.Fatal("multiple QUIC")
	}
	p.Seal()
	if !errors.Is(p.AddTCP(fake()), ErrClosed) {
		t.Fatal("late peer accepted")
	}
	if p.User() != f.User() || p.ChannelID() != f.ChannelID() || string(p.RouteMetadata()) != "owned-route" {
		t.Fatal("metadata lost")
	}
}
func TestCancellationAndClose(t *testing.T) {
	p, ctx := testPool(t)
	expired, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Open(expired, "owned.test", 80); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := p.Open(nil, "owned.test", 80); err == nil {
		t.Fatal("nil context")
	}
	if _, err := p.ReceiveUDP(nil); err == nil {
		t.Fatal("nil context")
	}
	if _, err := p.ReceiveApp(nil); err == nil {
		t.Fatal("nil context")
	}
	p.Close()
	p.Close()
	if _, err := p.Open(ctx, "owned.test", 80); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := p.ReceiveUDP(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := p.ReceiveApp(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestMergedUDPAppAndQUICSend(t *testing.T) {
	p, ctx := testPool(t)
	a, b := fake(), fake()
	p.AddTCP(a)
	p.AddQUIC(b)
	p.Seal()
	for i, peer := range []*fakePeer{a, b} {
		peer.udp <- protocol.UDPEnvelope{Data: []byte{byte(i)}}
		peer.app <- protocol.AppMessage{Type: 2, RequestID: uint32(i)}
	}
	seenUDP, seenApp := map[byte]bool{}, map[uint32]bool{}
	for i := 0; i < 2; i++ {
		u, err := p.ReceiveUDP(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seenUDP[u.Data[0]] = true
		m, err := p.ReceiveApp(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seenApp[m.RequestID] = true
	}
	if len(seenUDP) != 2 || len(seenApp) != 2 {
		t.Fatal("messages lost")
	}
	if err := p.SendUDP(ctx, protocol.UDPEnvelope{Data: []byte("u")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.sentUDP:
	case <-ctx.Done():
		t.Fatal("wrong UDP peer")
	}
	if err := p.SendApp(ctx, protocol.AppMessage{Type: 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.sentApp:
	case <-ctx.Done():
		t.Fatal("wrong application peer")
	}
}
func TestSocketIDsConcurrentAndExhaustion(t *testing.T) {
	var ids SocketIDs
	values := make(chan uint32, 128)
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := ids.Next()
			if e != nil {
				t.Error(e)
			}
			values <- v
		}()
	}
	wg.Wait()
	close(values)
	seen := map[uint32]bool{}
	for v := range values {
		if v == 0 || seen[v] {
			t.Fatal("duplicate ID")
		}
		seen[v] = true
	}
	ids.next.Store(0xfffffffe)
	if v, e := ids.Next(); e != nil || v != 0xffffffff {
		t.Fatal(v, e)
	}
	for i := 0; i < 2; i++ {
		if _, e := ids.Next(); !errors.Is(e, ErrSocketIDs) {
			t.Fatal("ID reused", e)
		}
	}
}

func TestNativeUDPRoundRobinChangesTCPSelectionOrder(t *testing.T) {
	p, ctx := testPool(t)
	peers := []*fakePeer{fake(), fake(), fake()}
	for _, peer := range peers {
		p.AddTCP(peer)
	}
	p.Seal()
	for _, want := range []int{0, 1, 2, 0, 1} {
		if err := p.SendUDP(ctx, protocol.UDPEnvelope{}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-peers[want].sentUDP:
		case <-ctx.Done():
			t.Fatal("UDP rotation differs from native")
		}
	}
	conn, err := p.Open(ctx, "owned.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if peers[2].opens != 1 {
		t.Fatal("least-loaded tie must reflect rotated TCP list")
	}
}

func TestTCPFirstRoutePreferencePreservesQUICApplicationControl(t *testing.T) {
	p, ctx := testPool(t)
	a, b := fake(), fake()
	p.AddTCP(a)
	p.AddQUIC(b)
	p.SetTCPFirst(true)
	p.Seal()
	conn, err := p.Open(ctx, "owned.test", 80)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if a.opens != 1 || b.opens != 0 {
		t.Fatal("TCP-first socket routing")
	}
	if err = p.SendUDP(ctx, protocol.UDPEnvelope{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.sentUDP:
	case <-ctx.Done():
		t.Fatal("TCP-first UDP routing")
	}
	if err = p.SendApp(ctx, protocol.AppMessage{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.sentApp:
	case <-ctx.Done():
		t.Fatal("application message must retain QUIC preference")
	}
	a.Close()
	conn, err = p.Open(ctx, "owned.test", 80)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if b.opens != 1 {
		t.Fatal("TCP-first must fall back to ready QUIC")
	}
}

func TestReplacementReservesLastPeerAndCompactsDeadMembers(t *testing.T) {
	p, ctx := testPool(t)
	started := make(chan bool, 1)
	finish := make(chan struct{})
	next := fake()
	p.SetRefill(func(ctx context.Context, quic bool) (Peer, error) {
		started <- quic
		select {
		case <-finish:
			return next, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	initial := fake()
	p.AddTCP(initial)
	p.Seal()
	initial.Close()
	select {
	case quic := <-started:
		if quic {
			t.Fatal("wrong slot kind")
		}
	case <-ctx.Done():
		t.Fatal("refill not started")
	}
	if p.Pending() != 1 {
		t.Fatal("missing reservation")
	}
	select {
	case <-p.Done():
		t.Fatal("last peer closed generation before replacement")
	default:
	}
	close(finish)
	c, err := p.Open(ctx, "owned.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	p.mu.Lock()
	members := len(p.members)
	p.mu.Unlock()
	if members != 1 {
		t.Fatal("dead peers retained", members)
	}
}
func TestInitiallyFailedSlotRefillAndTerminalFailure(t *testing.T) {
	p, ctx := testPool(t)
	started := make(chan struct{})
	release := make(chan struct{})
	p.SetRefill(func(ctx context.Context, quic bool) (Peer, error) {
		close(started)
		select {
		case <-release:
			return nil, io.ErrUnexpectedEOF
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err := p.RefillTCP(); err != nil {
		t.Fatal(err)
	}
	p.Seal()
	<-started
	select {
	case <-p.Done():
		t.Fatal("pending initial replacement lost")
	default:
	}
	close(release)
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatal("failed generation did not close")
	}
	if !errors.Is(p.Err(), io.ErrUnexpectedEOF) {
		t.Fatal(p.Err())
	}
	if !errors.Is(p.RefillQUIC(), ErrClosed) {
		t.Fatal("refill after close")
	}
}
func TestRefillCanceledAndInvalidPeerClosed(t *testing.T) {
	p, ctx := testPool(t)
	bad := fake()
	bad.id[0] = 2
	p.SetRefill(func(context.Context, bool) (Peer, error) { return bad, nil })
	p.RefillQUIC()
	p.Seal()
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatal("invalid replacement hung")
	}
	select {
	case <-bad.Done():
	default:
		t.Fatal("invalid replacement leaked")
	}
	q, _ := testPool(t)
	if !errors.Is(q.RefillTCP(), ErrUnsupported) {
		t.Fatal("refill without callback")
	}
	stopped := make(chan struct{})
	q.SetRefill(func(ctx context.Context, _ bool) (Peer, error) { <-ctx.Done(); close(stopped); return nil, ctx.Err() })
	q.RefillTCP()
	q.Seal()
	q.Close()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("refill cancellation lost")
	}
}
