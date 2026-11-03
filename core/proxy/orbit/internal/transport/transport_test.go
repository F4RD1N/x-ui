package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type lcgReader struct {
	state   uint32
	pending []byte
}

func (r *lcgReader) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.pending) == 0 {
			r.state = 1664525*r.state + 1013904223
			r.pending = binary.LittleEndian.AppendUint32(nil, r.state)
		}
		p[i] = r.pending[0]
		r.pending = r.pending[1:]
	}
	return len(p), nil
}
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type nativeFixture struct {
	TCP []struct {
		Seed                                          uint32
		ProxyHex, PrefaceHex, DataHex, EncodedDataHex string
	}
	QUIC []struct {
		Seed                                          uint32
		ProxyHex, InputHex, FormattedHex, RestoredHex string
	}
	QUICStreams []struct{ Name, Address, Hex string }
	TLSHellos   []struct {
		Seed       uint32
		SessionHex string
		Hybrid     bool
		Hex        string
	}
	HTTPHeaders []struct {
		Seed            uint32
		TLS             bool
		Host, Path, Hex string
	}
	ClientHellos []struct {
		Hex, SessionHex string
		CustomID        uint16
		Probe           int
	}
	OversizeDatagram struct{ PayloadSize, MSS, Error int }
	SSHMessages      []struct {
		Name string
		Seed uint32
		Hex  string
	}
}

func fixtures(t *testing.T) nativeFixture {
	t.Helper()
	b, e := os.ReadFile("testdata/native.json")
	if e != nil {
		t.Fatal(e)
	}
	var v nativeFixture
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestNativeTCPVectors(t *testing.T) {
	for _, v := range fixtures(t).TCP {
		header, key, err := MakeHeader(&lcgReader{state: v.Seed})
		if err != nil {
			t.Fatal(err)
		}
		proxy := unhex(t, v.ProxyHex)
		plain := binary.LittleEndian.AppendUint16(nil, uint16(len(proxy)))
		plain = append(plain, proxy...)
		c := ctr(key)
		c.XORKeyStream(plain, plain)
		preface := append(header, plain...)
		if !bytes.Equal(preface, unhex(t, v.PrefaceHex)) {
			t.Fatalf("preface native mismatch: %x", preface)
		}
		data := unhex(t, v.DataHex)
		c.XORKeyStream(data, data)
		if !bytes.Equal(data, unhex(t, v.EncodedDataHex)) {
			t.Fatal("continuous CTR native mismatch")
		}
	}
}

func TestNativeQUICVectors(t *testing.T) {
	for _, v := range fixtures(t).QUIC {
		formatted := unhex(t, v.FormattedHex)
		restored, meta, err := StripQUICInitial(formatted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(restored, unhex(t, v.RestoredHex)) {
			t.Fatal("native terminal restoration mismatch")
		}
		if meta.ConnectionID != 0x11223344 || hex.EncodeToString(meta.ChannelID[:]) != "00112233445566778899aabbccddeeff" {
			t.Fatal("metadata mismatch")
		}
		out, err := FormatQUICInitial(unhex(t, v.InputHex), QUICInitialOptions{
			Random: &lcgReader{state: v.Seed}, ConnectionID: meta.ConnectionID, ChannelID: meta.ChannelID, ProxyBuffer: meta.ProxyBuffer,
			EncodeUserInfo: func(r io.Reader) ([128]byte, error) {
				var salts [16]byte
				_, e := io.ReadFull(r, salts[:])
				return meta.UserInfo, e
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, formatted) {
			for i := range out {
				if i >= len(formatted) || out[i] != formatted[i] {
					t.Fatalf("native format mismatch at %d, sizes %d/%d", i, len(out), len(formatted))
				}
			}
			t.Fatal("size mismatch")
		}
	}
}

func TestHeaderAllLengthsAndFragmentation(t *testing.T) {
	seen := map[int]bool{}
	for seed := uint32(0); seed < 100; seed++ {
		h, key, e := MakeHeader(&lcgReader{state: seed})
		if e != nil {
			t.Fatal(e)
		}
		seen[len(h)] = true
		noise := []byte{0, 0, 0, 0, 0}
		packet := append(append([]byte(nil), noise...), h...)
		for split := 0; split < len(packet); split++ {
			consumed, _, ok := FindHeader(packet[:split])
			if ok {
				t.Fatal("accepted truncated")
			}
			n, k, ok := FindHeader(packet[consumed:])
			if !ok || k != key || consumed+n != len(packet) {
				t.Fatalf("fragment %d", split)
			}
		}
		for i := len(h) - 4; i < len(h); i++ {
			bad := append([]byte(nil), h...)
			bad[i] ^= 1
			_, _, ok := FindHeader(bad)
			if ok {
				t.Fatal("accepted corrupted CRC")
			}
		}
	}
	if len(seen) != 6 {
		t.Fatalf("tested lengths: %v", seen)
	}
}

func TestHeaderGolden(t *testing.T) {
	h := unhex(t, "5ff32132295047e9f67d0a16b3")
	n, k, ok := FindHeader(h)
	if !ok || n != len(h) || hex.EncodeToString(k[:]) != "4560728119ccdb0beef96008ca3c02c3" {
		t.Fatal("published native vector mismatch")
	}
	if _, _, err := MakeHeader(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

type fragmentedConn struct {
	net.Conn
	chunk int
}

func (c fragmentedConn) Read(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.Conn.Read(p)
}
func (c fragmentedConn) Write(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.Conn.Write(p)
}

func pair(t *testing.T, fragment int) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	var aa, bb net.Conn = a, b
	if fragment > 0 {
		aa = fragmentedConn{a, fragment}
		bb = fragmentedConn{b, fragment}
	}
	type result struct {
		c *Conn
		p []byte
		e error
	}
	ch := make(chan result, 1)
	go func() {
		c, p, e := Server(context.Background(), bb, Options{Timeout: time.Second})
		ch <- result{c, p, e}
	}()
	c, e := Client(context.Background(), aa, Options{ProxyBuffer: []byte("opaque-route"), Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	s := <-ch
	if s.e != nil {
		t.Fatal(s.e)
	}
	if string(s.p) != "opaque-route" {
		t.Fatal("proxy lost")
	}
	return c, s.c
}

func TestPairedDuplexFragmented(t *testing.T) {
	for _, fragment := range []int{0, 1, 3, 17} {
		t.Run(string(rune('a'+fragment)), func(t *testing.T) {
			c, s := pair(t, fragment)
			data := bytes.Repeat([]byte("forward-data-"), 300)
			reverse := bytes.Repeat([]byte("reverse-"), 300)
			var wg sync.WaitGroup
			wg.Add(2)
			errs := make(chan error, 2)
			go func() { defer wg.Done(); _, e := c.Write(data); errs <- e }()
			go func() { defer wg.Done(); _, e := s.Write(reverse); errs <- e }()
			got := make([]byte, len(data))
			if _, e := io.ReadFull(s, got); e != nil || !bytes.Equal(got, data) {
				t.Fatal("forward", e)
			}
			got = make([]byte, len(reverse))
			if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, reverse) {
				t.Fatal("reverse", e)
			}
			wg.Wait()
			for i := 0; i < 2; i++ {
				if e := <-errs; e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestConcurrentWritersKeepKeystream(t *testing.T) {
	c, s := pair(t, 0)
	const writers = 16
	const size = 1000
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(v byte) {
			defer wg.Done()
			if _, err := c.Write(bytes.Repeat([]byte{v}, size)); err != nil {
				t.Error(err)
			}
		}(byte(i))
	}
	got := make([]byte, writers*size)
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	counts := make([]int, writers)
	for _, v := range got {
		if int(v) >= writers {
			t.Fatal("corrupt")
		}
		counts[v]++
	}
	for _, n := range counts {
		if n != size {
			t.Fatal("lost concurrent data")
		}
	}
}

func TestHandshakeCancellationAndLimits(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := Server(ctx, a, Options{}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt")
	}
	a, b = net.Pipe()
	defer b.Close()
	go func(peer net.Conn) { _, _ = peer.Write(bytes.Repeat([]byte{0}, 100)); peer.Close() }(b)
	_, _, err := Server(context.Background(), a, Options{MaxScanBytes: 32})
	if !errors.Is(err, ErrHeader) {
		t.Fatal(err)
	}
	a, b = net.Pipe()
	defer b.Close()
	_, err = Client(context.Background(), a, Options{ProxyBuffer: make([]byte, 10), MaxProxyBytes: 5})
	if !errors.Is(err, ErrProxyBuffer) {
		t.Fatal(err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	start := time.Now()
	_, _, err := Server(context.Background(), a, Options{Timeout: 20 * time.Millisecond})
	if err == nil {
		t.Fatal("missing timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow timeout")
	}
}

func TestProxyLimitAndTruncatedEnvelope(t *testing.T) {
	for _, cut := range []int{1, 4} {
		a, b := net.Pipe()
		v := fixtures(t).TCP[1]
		packet := unhex(t, v.PrefaceHex)
		packet = packet[:len(packet)-cut]
		go func() { _, _ = b.Write(packet); b.Close() }()
		_, _, err := Server(context.Background(), a, Options{Timeout: time.Second})
		if err == nil {
			t.Fatal("accepted truncated proxy")
		}
	}
	a, b := net.Pipe()
	v := fixtures(t).TCP[1]
	go func() { _, _ = b.Write(unhex(t, v.PrefaceHex)); b.Close() }()
	_, _, err := Server(context.Background(), a, Options{MaxProxyBytes: 1})
	if !errors.Is(err, ErrProxyBuffer) {
		t.Fatal(err)
	}
}

func TestLoopbackTCPHalfClose(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		raw, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		s, _, e := Server(context.Background(), raw, Options{})
		if e != nil {
			done <- e
			return
		}
		defer s.Close()
		p, e := io.ReadAll(s)
		if e == nil {
			_, e = s.Write(append(p, []byte("ack")...))
		}
		if e == nil {
			e = s.CloseWrite()
		}
		done <- e
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Client(context.Background(), raw, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	p, err := io.ReadAll(c)
	if err != nil || string(p) != "helloack" {
		t.Fatalf("reverse after FIN: %q %v", p, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMalformedQUIC(t *testing.T) {
	v := fixtures(t).QUIC[0]
	valid := unhex(t, v.FormattedHex)
	for n := 0; n < len(valid); n++ {
		if _, _, err := StripQUICInitial(valid[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, input := range [][]byte{nil, {0x80}, {0xc0}, {0xff, 0xff}, append(append([]byte(nil), valid...), 0)} {
		if _, _, err := StripQUICInitial(input); err == nil {
			t.Fatal("accepted malformed")
		}
	}
	for _, value := range []int{0, 63, 64, 255, 4096, 16383} {
		b, err := appendReferenceVarint(nil, value)
		if err != nil {
			t.Fatal(err)
		}
		v, n, err := ParseReferenceVarint(b)
		if err != nil || n != len(b) || v != value {
			t.Fatal(value, v, n, err)
		}
	}
	if _, err := appendReferenceVarint(nil, 16384); err == nil {
		t.Fatal("large varint accepted")
	}
}

func FuzzHeader(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		n, _, ok := FindHeader(b)
		if n < 0 || n > len(b) {
			t.Fatal("invalid consumed")
		}
		if ok && n < 10 {
			t.Fatal("short accepted")
		}
	})
}
func FuzzQUICInitial(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		out, _, e := StripQUICInitial(b)
		if e == nil && len(out) > len(b) {
			t.Fatal("strip expanded")
		}
	})
}
