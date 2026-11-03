package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
	"testing/iotest"
)

func TestHeader(t *testing.T) {
	for op := Opcode(0); op < 32; op++ {
		for key := uint8(0); key < 8; key++ {
			b := Header(op, key)
			if b != byte(op)<<3|key {
				t.Fatalf("Header(%d, %d) = %#x", op, key, b)
			}
			gop, gkey := SplitHeader(b)
			if gop != op || gkey != key {
				t.Fatalf("SplitHeader(Header(%d, %d)) = %d, %d", op, key, gop, gkey)
			}
		}
	}
	if b := Header(ControlV1, 0xff); b != 0x27 {
		t.Errorf("Header masks the key id: got %#x, want 0x27", b)
	}
}

func TestOpcodeClasses(t *testing.T) {
	control := map[Opcode]bool{1: true, 2: true, 3: true, 4: true, 5: true, 7: true, 8: true, 10: true, 11: true}
	reset := map[Opcode]bool{1: true, 2: true, 3: true, 7: true, 8: true, 10: true}
	data := map[Opcode]bool{6: true, 9: true}
	names := map[Opcode]string{
		1: "P_CONTROL_HARD_RESET_CLIENT_V1", 2: "P_CONTROL_HARD_RESET_SERVER_V1",
		3: "P_CONTROL_SOFT_RESET_V1", 4: "P_CONTROL_V1", 5: "P_ACK_V1", 6: "P_DATA_V1",
		7: "P_CONTROL_HARD_RESET_CLIENT_V2", 8: "P_CONTROL_HARD_RESET_SERVER_V2", 9: "P_DATA_V2",
		10: "P_CONTROL_HARD_RESET_CLIENT_V3", 11: "P_CONTROL_WKC_V1",
		0: "P_OPCODE_0", 12: "P_OPCODE_12", 31: "P_OPCODE_31",
	}
	for op := Opcode(0); op < 32; op++ {
		if op.IsControl() != control[op] || op.IsReset() != reset[op] || op.IsData() != data[op] {
			t.Errorf("%d: IsControl %v IsReset %v IsData %v", op, op.IsControl(), op.IsReset(), op.IsData())
		}
		if want, ok := names[op]; ok && op.String() != want {
			t.Errorf("%d: String = %q, want %q", op, op.String(), want)
		}
	}
}

var (
	sidA = SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	sidB = SessionID{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
)

func TestMarshalVectors(t *testing.T) {
	tests := []struct {
		name string
		p    ControlPacket
		want []byte
	}{
		{
			"client reset",
			ControlPacket{Opcode: ControlHardResetClientV2, SessionID: sidA},
			[]byte{0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0},
		},
		{
			"server reset with ack",
			ControlPacket{Opcode: ControlHardResetServerV2, KeyID: 0, SessionID: sidB, Acks: []PacketID{0}, RemoteSessionID: sidA},
			[]byte{0x40, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0},
		},
		{
			"control with two acks and payload",
			ControlPacket{Opcode: ControlV1, KeyID: 5, SessionID: sidA, Acks: []PacketID{0x01020304, 7}, RemoteSessionID: sidB, PacketID: 0x0a0b0c0d, Payload: []byte("hi")},
			[]byte{0x25, 1, 2, 3, 4, 5, 6, 7, 8, 2, 1, 2, 3, 4, 0, 0, 0, 7, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0x0a, 0x0b, 0x0c, 0x0d, 'h', 'i'},
		},
		{
			"ack only",
			ControlPacket{Opcode: AckV1, KeyID: 1, SessionID: sidA, Acks: []PacketID{9}, RemoteSessionID: sidB},
			[]byte{0x29, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 9, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		},
		{
			"ack only ignores message id and payload",
			ControlPacket{Opcode: AckV1, SessionID: sidA, PacketID: 5, Payload: []byte("x")},
			[]byte{0x28, 1, 2, 3, 4, 5, 6, 7, 8, 0},
		},
		{
			"wkc",
			ControlPacket{Opcode: ControlWKCV1, KeyID: 0, SessionID: sidA, PacketID: 1},
			[]byte{0x58, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1},
		},
	}
	for _, tc := range tests {
		got := Marshal(&tc.p)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: Marshal = %x, want %x", tc.name, got, tc.want)
		}
		if body := AppendBody([]byte("prefix"), &tc.p); !bytes.Equal(body, append([]byte("prefix"), tc.want[9:]...)) {
			t.Errorf("%s: AppendBody = %x", tc.name, body)
		}
	}
}

func roundTripPackets() []ControlPacket {
	big := bytes.Repeat([]byte{0xee}, 1400)
	var max []PacketID
	for i := 0; i < MaxAcks; i++ {
		max = append(max, 0xfffffff0+PacketID(i)) // in PacketID: 0xfffffff0 overflows a 32-bit int
	}
	return []ControlPacket{
		{Opcode: ControlHardResetClientV1, SessionID: sidA, Payload: []byte("v1")},
		{Opcode: ControlHardResetServerV1, KeyID: 7, SessionID: sidB, Acks: []PacketID{0}, RemoteSessionID: sidA, PacketID: 0},
		{Opcode: ControlSoftResetV1, KeyID: 1, SessionID: sidA, PacketID: 12},
		{Opcode: ControlV1, KeyID: 2, SessionID: sidA, Acks: max, RemoteSessionID: sidB, PacketID: 3, Payload: big},
		{Opcode: AckV1, SessionID: sidA, Acks: max, RemoteSessionID: sidB},
		{Opcode: AckV1, SessionID: sidA},
		{Opcode: ControlHardResetClientV2, SessionID: sidA},
		{Opcode: ControlHardResetServerV2, SessionID: sidB, Acks: []PacketID{0}, RemoteSessionID: sidA, Payload: []byte{0, 1}},
		{Opcode: ControlHardResetClientV3, SessionID: sidA, PacketID: 0xffffffff},
		{Opcode: ControlWKCV1, KeyID: 4, SessionID: sidA, Acks: []PacketID{1}, RemoteSessionID: sidB, PacketID: 1, Payload: []byte("w")},
	}
}

func TestRoundTrip(t *testing.T) {
	for i, p := range roundTripPackets() {
		b := Marshal(&p)
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatalf("packet %d (%v): Unmarshal: %v", i, p.Opcode, err)
		}
		want := p
		if len(want.Payload) == 0 {
			want.Payload = got.Payload // nil vs empty
		}
		if !reflect.DeepEqual(*got, want) {
			t.Fatalf("packet %d: got %+v, want %+v", i, *got, want)
		}
		if len(got.Payload) > 0 && &got.Payload[0] != &b[len(b)-len(got.Payload)] {
			t.Errorf("packet %d: Payload does not alias the input", i)
		}
		// ParseBody alone, starting from a dirty packet.
		q := ControlPacket{Opcode: p.Opcode, Acks: []PacketID{99}, RemoteSessionID: sidB, PacketID: 77, Payload: []byte("stale")}
		if err := ParseBody(&q, b[9:]); err != nil {
			t.Fatalf("packet %d: ParseBody: %v", i, err)
		}
		q.KeyID, q.SessionID = p.KeyID, p.SessionID
		if len(q.Payload) == 0 {
			q.Payload = want.Payload
		}
		if !reflect.DeepEqual(q, want) {
			t.Fatalf("packet %d: ParseBody into a used packet: got %+v, want %+v", i, q, want)
		}
	}
}

func TestUnmarshalMalformed(t *testing.T) {
	ctl := func(op Opcode, body ...byte) []byte {
		return append([]byte{Header(op, 0), 1, 2, 3, 4, 5, 6, 7, 8}, body...)
	}
	acks := func(n int) []byte {
		b := []byte{byte(n)}
		for i := 0; i < n; i++ {
			b = binary.BigEndian.AppendUint32(b, uint32(i))
		}
		return append(b, sidB[:]...)
	}
	tests := []struct {
		name string
		b    []byte
		err  error
	}{
		{"empty", nil, ErrShort},
		{"header only", []byte{0x20}, ErrShort},
		{"8-byte session id", ctl(ControlV1)[:8], ErrShort},
		{"no ack count", ctl(ControlV1), ErrShort},
		{"no message id", ctl(ControlV1, 0), ErrShort},
		{"short message id", ctl(ControlV1, 0, 0, 0, 1), ErrShort},
		{"truncated ack", ctl(ControlV1, 1, 0, 0, 0), ErrShort},
		{"no remote session id", ctl(ControlV1, 1, 0, 0, 0, 5), ErrShort},
		{"short remote session id", ctl(ControlV1, 1, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7), ErrShort},
		{"ack-only short remote session id", ctl(AckV1, 1, 0, 0, 0, 5, 1, 2), ErrShort},
		{"ack-only no ack count", ctl(AckV1), ErrShort},
		{"9 acks", ctl(ControlV1, acks(9)...), ErrTooMany},
		{"255 acks", ctl(ControlV1, 255), ErrTooMany},
		{"8 acks then nothing", ctl(ControlV1, acks(8)...), ErrShort},
		{"P_DATA_V1", ctl(DataV1, 0, 0, 0, 0, 0), ErrBadOpcode},
		{"P_DATA_V2", ctl(DataV2, 0, 0, 0, 0, 0), ErrBadOpcode},
		{"opcode 0", ctl(0, 0, 0, 0, 0, 0), ErrBadOpcode},
		{"opcode 12", ctl(12, 0, 0, 0, 0, 0), ErrBadOpcode},
		{"opcode 31", ctl(31, 0, 0, 0, 0, 0), ErrBadOpcode},
	}
	for _, tc := range tests {
		p, err := Unmarshal(tc.b)
		if !errors.Is(err, tc.err) || p != nil {
			t.Errorf("%s: Unmarshal = %v, %v; want %v", tc.name, p, err, tc.err)
		}
	}
	// Ack-only packets ignore anything after the remote session id.
	p, err := Unmarshal(ctl(AckV1, 1, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad))
	if err != nil || p.PacketID != 0 || p.Payload != nil || len(p.Acks) != 1 || p.Acks[0] != 5 {
		t.Errorf("ack-only with trailing bytes: %+v, %v", p, err)
	}
	if err := ParseBody(&ControlPacket{Opcode: ControlV1}, nil); !errors.Is(err, ErrShort) {
		t.Errorf("ParseBody(nil) = %v", err)
	}
}

func TestAckBounds(t *testing.T) {
	for n := 0; n <= 255; n++ {
		body := []byte{byte(n)}
		for i := 0; i < n; i++ {
			body = binary.BigEndian.AppendUint32(body, uint32(1000+i))
		}
		if n > 0 {
			body = append(body, sidB[:]...)
		}
		body = append(body, 0, 0, 0, 42, 'p')
		p := ControlPacket{Opcode: ControlV1}
		err := ParseBody(&p, body)
		if n <= MaxAcks {
			if err != nil || len(p.Acks) != n || p.PacketID != 42 || string(p.Payload) != "p" {
				t.Fatalf("%d acks: %+v, %v", n, p, err)
			}
			for i, a := range p.Acks {
				if a != PacketID(1000+i) {
					t.Fatalf("%d acks: ack %d = %d", n, i, a)
				}
			}
		} else if !errors.Is(err, ErrTooMany) {
			t.Fatalf("%d acks: err = %v, want ErrTooMany", n, err)
		}
	}
}

func TestDataHeader(t *testing.T) {
	tests := []struct {
		keyID  uint8
		peerID uint32
		want   []byte
	}{
		{0, NoPeerID, []byte{0x30}},
		{7, NoPeerID, []byte{0x37}},
		{0, 0, []byte{0x48, 0, 0, 0}},
		{2, 0x123456, []byte{0x4a, 0x12, 0x34, 0x56}},
		{1, 0xfffffe, []byte{0x49, 0xff, 0xff, 0xfe}},
	}
	for _, tc := range tests {
		b := AppendDataHeader([]byte{0xaa}, tc.keyID, tc.peerID)
		if !bytes.Equal(b[1:], tc.want) || b[0] != 0xaa {
			t.Errorf("AppendDataHeader(%d, %#x) = %x, want %x", tc.keyID, tc.peerID, b[1:], tc.want)
		}
		op, key, peer, n, err := ParseDataHeader(append(b[1:], 0xde, 0xad))
		wantOp := DataV2
		if tc.peerID == NoPeerID {
			wantOp = DataV1
		}
		if err != nil || op != wantOp || key != tc.keyID || peer != tc.peerID || n != len(tc.want) {
			t.Errorf("ParseDataHeader(%x) = %v %d %#x %d %v", b[1:], op, key, peer, n, err)
		}
	}
	bad := []struct {
		b   []byte
		err error
	}{
		{nil, ErrShort},
		{[]byte{0x48}, ErrShort},
		{[]byte{0x48, 0, 0}, ErrShort},
		{[]byte{0x20, 0, 0, 0}, ErrBadOpcode},
		{[]byte{0x00}, ErrBadOpcode},
		{[]byte{0xf8}, ErrBadOpcode},
	}
	for _, tc := range bad {
		if _, _, _, n, err := ParseDataHeader(tc.b); !errors.Is(err, tc.err) || n != 0 {
			t.Errorf("ParseDataHeader(%x) = %d, %v; want %v", tc.b, n, err, tc.err)
		}
	}
}

func TestAppendFrame(t *testing.T) {
	b, err := AppendFrame([]byte{9}, []byte("abc"))
	if err != nil || !bytes.Equal(b, []byte{9, 0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("AppendFrame = %x, %v", b, err)
	}
	max := make([]byte, MaxPacketSize)
	b, err = AppendFrame(nil, max)
	if err != nil || len(b) != MaxPacketSize+2 || b[0] != 0xff || b[1] != 0xff {
		t.Fatalf("AppendFrame(65535 bytes) = %d bytes, %v", len(b), err)
	}
	dst := []byte{1, 2}
	b, err = AppendFrame(dst, make([]byte, MaxPacketSize+1))
	if !errors.Is(err, ErrTooLarge) || !bytes.Equal(b, dst) {
		t.Fatalf("AppendFrame(65536 bytes) = %d bytes, %v", len(b), err)
	}
	if b, err = AppendFrame(nil, nil); err != nil || !bytes.Equal(b, []byte{0, 0}) {
		t.Fatalf("AppendFrame(empty) = %x, %v", b, err)
	}
}

func frames(t testing.TB, pkts ...[]byte) []byte {
	t.Helper()
	var b []byte
	for _, p := range pkts {
		var err error
		if b, err = AppendFrame(b, p); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestFrameReader(t *testing.T) {
	big := bytes.Repeat([]byte{0x5a}, 3000)
	stream := frames(t, []byte("one"), nil, big, []byte("after"), make([]byte, MaxPacketSize))
	for _, wrap := range []struct {
		name string
		r    func(io.Reader) io.Reader
	}{
		{"whole", func(r io.Reader) io.Reader { return r }},
		{"one byte", iotest.OneByteReader},
		{"half", iotest.HalfReader},
		{"data+EOF", iotest.DataErrReader},
	} {
		fr := NewFrameReader(wrap.r(bytes.NewReader(stream)))
		buf := make([]byte, 2048)
		expect := func(want []byte, wantErr error) {
			t.Helper()
			n, err := fr.ReadPacket(buf)
			if !errors.Is(err, wantErr) || (wantErr == nil && !bytes.Equal(buf[:n], want)) {
				t.Fatalf("%s: ReadPacket = %d, %v; want %d bytes, %v", wrap.name, n, err, len(want), wantErr)
			}
			if wantErr != nil && n != 0 {
				t.Fatalf("%s: ReadPacket returned %d bytes with %v", wrap.name, n, err)
			}
		}
		expect([]byte("one"), nil)
		expect(nil, nil)
		expect(nil, io.ErrShortBuffer) // 3000 > 2048: skipped, stream stays in sync
		expect([]byte("after"), nil)
		expect(nil, io.ErrShortBuffer) // 65535 bytes
		expect(nil, io.EOF)
	}
	// A buffer of exactly the packet size is enough.
	fr := NewFrameReader(bytes.NewReader(frames(t, big)))
	if n, err := fr.ReadPacket(make([]byte, len(big))); err != nil || n != len(big) {
		t.Fatalf("exact buffer: %d, %v", n, err)
	}
}

func TestFrameReaderTruncated(t *testing.T) {
	full := frames(t, []byte("hello"), bytes.Repeat([]byte{1}, 100))
	tests := []struct {
		name  string
		cut   int // bytes of full kept
		buf   int
		first error
	}{
		{"clean EOF", 0, 64, io.EOF},
		{"half a length", 1, 64, io.ErrUnexpectedEOF},
		{"length only", 2, 64, io.ErrUnexpectedEOF},
		{"partial body", 5, 64, io.ErrUnexpectedEOF},
		{"oversize length only", 7 + 2, 64, io.ErrUnexpectedEOF},
		{"oversize partial body", 7 + 50, 64, io.ErrUnexpectedEOF},
	}
	for _, tc := range tests {
		fr := NewFrameReader(bytes.NewReader(full[:tc.cut]))
		buf := make([]byte, tc.buf)
		var err error
		if tc.cut >= 7 {
			if _, err = fr.ReadPacket(buf); err != nil {
				t.Fatalf("%s: first packet: %v", tc.name, err)
			}
		}
		_, err = fr.ReadPacket(buf)
		if !errors.Is(err, tc.first) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.first)
		}
	}
	// Errors from the underlying reader come through unchanged.
	boom := errors.New("boom")
	fr := NewFrameReader(io.MultiReader(bytes.NewReader([]byte{0, 9, 1}), iotest.ErrReader(boom)))
	if _, err := fr.ReadPacket(make([]byte, 64)); !errors.Is(err, boom) {
		t.Errorf("reader error: %v", err)
	}
	fr = NewFrameReader(io.MultiReader(bytes.NewReader([]byte{0, 99, 1}), iotest.ErrReader(boom)))
	if _, err := fr.ReadPacket(make([]byte, 64)); !errors.Is(err, boom) {
		t.Errorf("reader error while skipping: %v", err)
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, p := range roundTripPackets() {
		f.Add(Marshal(&p))
	}
	f.Add([]byte{})
	f.Add([]byte{0x28, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Unmarshal(b)
		if err != nil {
			if p != nil {
				t.Fatalf("packet and error")
			}
			return
		}
		if !p.Opcode.IsControl() || len(p.Acks) > MaxAcks {
			t.Fatalf("accepted %+v", p)
		}
		m := Marshal(p)
		if p.HasMessageID() {
			if !bytes.Equal(m, b) {
				t.Fatalf("Marshal(Unmarshal(b)) = %x, b = %x", m, b)
			}
		} else if !bytes.HasPrefix(b, m) {
			t.Fatalf("P_ACK_V1: Marshal(Unmarshal(b)) = %x is not a prefix of %x", m, b)
		}
	})
}

func FuzzParseBody(f *testing.F) {
	for _, p := range roundTripPackets() {
		f.Add(byte(p.Opcode), AppendBody(nil, &p))
	}
	f.Fuzz(func(t *testing.T, op byte, body []byte) {
		p := ControlPacket{Opcode: Opcode(op)}
		if err := ParseBody(&p, body); err != nil {
			return
		}
		if len(p.Acks) > MaxAcks {
			t.Fatalf("%d acks", len(p.Acks))
		}
		m := AppendBody(nil, &p)
		if p.HasMessageID() && !bytes.Equal(m, body) || !bytes.HasPrefix(body, m) {
			t.Fatalf("AppendBody(ParseBody(b)) = %x, b = %x", m, body)
		}
	})
}

func FuzzParseDataHeader(f *testing.F) {
	f.Add([]byte{0x30})
	f.Add([]byte{0x4a, 1, 2, 3, 4})
	f.Add([]byte{0x48, 1})
	f.Add([]byte{0x20})
	f.Fuzz(func(t *testing.T, b []byte) {
		op, key, peer, n, err := ParseDataHeader(b)
		if err != nil {
			return
		}
		if n > len(b) || !op.IsData() {
			t.Fatalf("header length %d of %d bytes, op %v", n, len(b), op)
		}
		if got := AppendDataHeader(nil, key, peer); !bytes.Equal(got, b[:n]) {
			// P_DATA_V2 with peer id 0xFFFFFF re-encodes as P_DATA_V1.
			if !(op == DataV2 && peer == NoPeerID) {
				t.Fatalf("AppendDataHeader = %x, header %x", got, b[:n])
			}
		}
	})
}

func FuzzFrameReader(f *testing.F) {
	f.Add(uint16(64), frames(f, []byte("abc"), make([]byte, 100), []byte("x")))
	f.Add(uint16(0), []byte{0, 0, 0, 1})
	f.Add(uint16(10), []byte{0xff, 0xff, 1, 2})
	f.Fuzz(func(t *testing.T, size uint16, stream []byte) {
		fr := NewFrameReader(bytes.NewReader(stream))
		buf := make([]byte, int(size)%4096)
		consumed := 0
		for i := 0; ; i++ {
			if i > len(stream) {
				t.Fatalf("more packets than bytes")
			}
			if consumed+2 > len(stream) {
				if _, err := fr.ReadPacket(buf); err == nil {
					t.Fatalf("packet past the end of the stream")
				}
				return
			}
			l := int(binary.BigEndian.Uint16(stream[consumed:]))
			n, err := fr.ReadPacket(buf)
			switch {
			case consumed+2+l > len(stream):
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("truncated frame: %d, %v", n, err)
				}
				return
			case l > len(buf):
				if !errors.Is(err, io.ErrShortBuffer) || n != 0 {
					t.Fatalf("oversize frame: %d, %v", n, err)
				}
			default:
				if err != nil || n != l || !bytes.Equal(buf[:n], stream[consumed+2:consumed+2+l]) {
					t.Fatalf("frame of %d: %d, %v", l, n, err)
				}
			}
			consumed += 2 + l
		}
	})
}
