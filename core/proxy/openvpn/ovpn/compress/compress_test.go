package compress

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"slices"
	"sync"
	"testing"
)

// The vectors come from the system liblzo2 and liblz4 through
// testdata/gen_vectors.py; see that script for what each part means.
type vectorFile struct {
	LZO       string     `json:"lzo"`
	LZ4       string     `json:"lz4"`
	Vectors   []vector   `json:"vectors"`
	Crafted   []crafted  `json:"crafted"`
	Mutations []mutation `json:"mutations"`
}

type vector struct {
	Name     string `json:"name"`
	Input    []byte `json:"input"`
	LZ4      []byte `json:"lz4"`
	LZO1X1   []byte `json:"lzo1x_1_15"`
	LZO1X999 []byte `json:"lzo1x_999"`
}

// verdict is the reference library's result for a stream.
type verdict struct {
	Cap       int    `json:"cap"`
	OK        bool   `json:"ok"`
	Code      any    `json:"code"`
	OutLen    int    `json:"out_len"`
	OutSHA256 string `json:"out_sha256"`
}

type crafted struct {
	Name   string `json:"name"`
	Codec  string `json:"codec"` // "lz4" or "lzo"
	Stream []byte `json:"stream"`
	verdict
}

type mutation struct {
	Vector string `json:"vector"`
	Codec  string `json:"codec"` // "lz4", "lzo1x_1_15" or "lzo1x_999"
	Op     string `json:"op"`
	Pos    int    `json:"pos"`
	Val    int    `json:"val"`
	verdict
}

var loadVectors = sync.OnceValues(func() (*vectorFile, error) {
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		return nil, err
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &f, nil
})

func vectors(t testing.TB) *vectorFile {
	t.Helper()
	f, err := loadVectors()
	if err != nil {
		t.Fatalf("loading testdata/vectors.json: %v", err)
	}
	return f
}

func (v *vector) compressed(codec string) []byte {
	switch codec {
	case "lz4":
		return v.LZ4
	case "lzo1x_1_15":
		return v.LZO1X1
	case "lzo1x_999":
		return v.LZO1X999
	}
	panic("unknown codec " + codec)
}

func decoder(codec string) func(dst, src []byte, maxOut int) ([]byte, error) {
	if codec == "lz4" {
		return DecompressLZ4Block
	}
	return DecompressLZO1X
}

var codecs = []string{"lz4", "lzo1x_1_15", "lzo1x_999"}

func shortHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:16])
}

// checkErr fails unless err is one of the decoders' documented errors.
func checkErr(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTooBig) {
		t.Errorf("%s: error %v is neither ErrCorrupt nor ErrTooBig", what, err)
	}
}

func TestParse(t *testing.T) {
	lzo := []struct {
		arg  string
		want Mode
		ok   bool
	}{
		{"", LZO, true}, {"yes", LZO, true}, {"no", LZO, true}, {"adaptive", LZO, true},
		{"maybe", None, false}, {"YES", None, false}, {"lz4", None, false},
	}
	for _, tc := range lzo {
		m, err := ParseCompLZO(tc.arg)
		if (err == nil) != tc.ok || (tc.ok && m != tc.want) {
			t.Errorf("ParseCompLZO(%q) = %v, %v; want %v ok=%v", tc.arg, m, err, tc.want, tc.ok)
		}
	}
	comp := []struct {
		arg  string
		want Mode
		ok   bool
	}{
		{"", Swap, true}, {"stub", Swap, true}, {"lz4", Swap, true},
		{"stub-v2", V2, true}, {"lz4-v2", V2, true},
		{"lzo", LZO, true}, {"migrate", None, true},
		{"zstd", None, false}, {"lz4v2", None, false}, {"LZ4", None, false}, {"yes", None, false},
	}
	for _, tc := range comp {
		m, err := ParseCompress(tc.arg)
		if (err == nil) != tc.ok || (tc.ok && m != tc.want) {
			t.Errorf("ParseCompress(%q) = %v, %v; want %v ok=%v", tc.arg, m, err, tc.want, tc.ok)
		}
	}
}

func TestModeString(t *testing.T) {
	for m, want := range map[Mode]string{None: "none", LZO: "lzo", Swap: "swap", V2: "v2", Mode(9): "Mode(9)", Mode(-1): "Mode(-1)"} {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(m), got, want)
		}
	}
}

// Every vector decompresses to its input, with maxOut exactly its size, and
// one byte less is ErrTooBig.
func TestDecompressVectors(t *testing.T) {
	f := vectors(t)
	t.Logf("vectors from liblzo2 %s and liblz4 %s", f.LZO, f.LZ4)
	prefix := []byte("existing dst bytes")
	for _, v := range f.Vectors {
		for _, codec := range codecs {
			c := v.compressed(codec)
			dec := decoder(codec)
			got, err := dec(nil, c, len(v.Input))
			if err != nil || !bytes.Equal(got, v.Input) {
				t.Errorf("%s/%s: got %d bytes, %v; want the %d-byte input", v.Name, codec, len(got), err, len(v.Input))
				continue
			}
			got, err = dec(slices.Clone(prefix), c, len(v.Input))
			if err != nil || !bytes.Equal(got[:len(prefix)], prefix) || !bytes.Equal(got[len(prefix):], v.Input) {
				t.Errorf("%s/%s with a dst prefix: %v", v.Name, codec, err)
			}
			if len(v.Input) > 0 {
				got, err = dec(prefix, c, len(v.Input)-1)
				if !errors.Is(err, ErrTooBig) || !bytes.Equal(got, prefix) {
					t.Errorf("%s/%s with maxOut one short: %d bytes, %v; want dst back and ErrTooBig", v.Name, codec, len(got), err)
				}
			}
		}
	}
}

// Hand-written streams, one per instruction kind and error, against the
// reference decoders' verdicts.
func TestDecompressCrafted(t *testing.T) {
	// liblz4 rejects a block whose last sequence starts less than 8 bytes
	// before the end after a match (its end-of-block parsing restriction);
	// this decoder is more lenient and decodes it.
	lenient := map[string]bool{"lz4-short-last-literals": true}
	for _, c := range vectors(t).Crafted {
		dec := DecompressLZO1X
		if c.Codec == "lz4" {
			dec = DecompressLZ4Block
		}
		got, err := dec(nil, c.Stream, c.Cap)
		switch {
		case c.Name == "lz4-offset-zero":
			if !errors.Is(err, errLZ4ZeroOffset) {
				t.Errorf("%s: %v, want errLZ4ZeroOffset", c.Name, err)
			}
		case c.OK:
			if err != nil || len(got) != c.OutLen || shortHash(got) != c.OutSHA256 {
				t.Errorf("%s: got %d bytes, %v; reference decoded %d bytes", c.Name, len(got), err, c.OutLen)
			}
		case lenient[c.Name]:
			if err != nil {
				t.Errorf("%s: %v; this decoder accepts it", c.Name, err)
			}
		default:
			if err == nil {
				t.Errorf("%s: decoded %d bytes; reference failed with %v", c.Name, len(got), c.Code)
				continue
			}
			want := ErrCorrupt
			if bytes.Contains([]byte(c.Name), []byte("overrun")) {
				want = ErrTooBig
			}
			if !errors.Is(err, want) {
				t.Errorf("%s: %v, want %v", c.Name, err, want)
			}
		}
	}
}

func mutate(b []byte, op string, pos, val int) []byte {
	m := slices.Clone(b)
	switch op {
	case "trunc":
		return m[:pos]
	case "set":
		m[pos] = byte(val)
	case "xor":
		m[pos] ^= byte(val)
	case "delete":
		return slices.Delete(m, pos, pos+1)
	case "insert":
		return slices.Insert(m, pos, byte(val))
	default:
		panic("unknown mutation " + op)
	}
	return m
}

// Corrupted vectors. LZO1X must agree with lzo1x_decompress_safe both ways.
// LZ4 must decode everything liblz4 decodes, identically, except blocks
// with a match offset of 0 (see DecompressLZ4Block); where liblz4 fails,
// this decoder may still decode (it lacks liblz4's capacity-dependent
// end-of-block restrictions).
func TestDecompressMutations(t *testing.T) {
	f := vectors(t)
	byName := map[string]*vector{}
	for i := range f.Vectors {
		byName[f.Vectors[i].Name] = &f.Vectors[i]
	}
	var lz4Lenient, lz4Offset0, failures int
	prefix := []byte{1, 2, 3}
	for _, m := range f.Mutations {
		v := byName[m.Vector]
		if v == nil {
			t.Fatalf("mutation of unknown vector %q", m.Vector)
		}
		src := mutate(v.compressed(m.Codec), m.Op, m.Pos, m.Val)
		got, err := decoder(m.Codec)(slices.Clone(prefix), src, m.Cap)
		what := m.Vector + "/" + m.Codec + "/" + m.Op
		if err != nil {
			checkErr(t, what, err)
			if !bytes.Equal(got, prefix) {
				t.Errorf("%s: failed but returned %d bytes, not dst", what, len(got))
			}
		} else if !bytes.Equal(got[:len(prefix)], prefix) {
			t.Errorf("%s: dst prefix overwritten", what)
		}
		ok := err == nil
		if ok {
			got = got[len(prefix):]
		}
		switch {
		case m.Codec == "lz4" && m.OK && errors.Is(err, errLZ4ZeroOffset):
			lz4Offset0++
		case m.Codec == "lz4" && !m.OK && ok:
			lz4Lenient++
		case ok != m.OK:
			failures++
			t.Errorf("%s at %d (val %d): ok=%v (%v), reference ok=%v (%v)", what, m.Pos, m.Val, ok, err, m.OK, m.Code)
		case ok && (len(got) != m.OutLen || shortHash(got) != m.OutSHA256):
			failures++
			t.Errorf("%s at %d (val %d): %d bytes differ from the reference's %d", what, m.Pos, m.Val, len(got), m.OutLen)
		}
	}
	t.Logf("%d mutations: %d failures; lz4: %d decoded where liblz4 refused, %d refused for offset 0",
		len(f.Mutations), failures, lz4Lenient, lz4Offset0)
}

// Matches may not reach into what dst held before.
func TestMatchesStayInOutput(t *testing.T) {
	dst := []byte("abcdef")
	// LZ4: no literals, a 4-byte match 1 back, then an empty last sequence.
	if got, err := DecompressLZ4Block(dst, []byte{0x00, 0x01, 0x00, 0x00}, 100); !errors.Is(err, errLZ4Distance) || len(got) != len(dst) {
		t.Errorf("lz4 match into dst: %q, %v", got, err)
	}
	// LZO1X: one literal, then an M1 match 2 back.
	if got, err := DecompressLZO1X(dst, []byte{18, 'a', 0x04, 0x00, 0x11, 0x00, 0x00}, 100); !errors.Is(err, errLZODistance) || len(got) != len(dst) {
		t.Errorf("lzo match into dst: %q, %v", got, err)
	}
	// maxOut <= 0 allows nothing, but an empty stream still decodes.
	for _, max := range []int{0, -5} {
		if got, err := DecompressLZ4Block(nil, []byte{0x00}, max); err != nil || len(got) != 0 {
			t.Errorf("empty lz4 block, maxOut %d: %v", max, err)
		}
		if _, err := DecompressLZ4Block(nil, []byte{0x10, 'a'}, max); !errors.Is(err, ErrTooBig) {
			t.Errorf("one lz4 literal, maxOut %d: %v", max, err)
		}
		if _, err := DecompressLZO1X(nil, []byte{18, 'a', 0x11, 0, 0}, max); !errors.Is(err, ErrTooBig) {
			t.Errorf("one lzo literal, maxOut %d: %v", max, err)
		}
	}
}

// Long length extensions are bounded before they can overflow.
func TestHugeLengths(t *testing.T) {
	// LZ4 literal count of 15 + 255*n, far beyond the input.
	src := append([]byte{0xF0}, bytes.Repeat([]byte{0xFF}, 1000)...)
	if _, err := DecompressLZ4Block(nil, append(src, 0), 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Errorf("lz4 literal count beyond input: %v", err)
	}
	// LZ4 match length far beyond maxOut.
	src = append([]byte{0x1F, 'a', 1, 0}, bytes.Repeat([]byte{0xFF}, 1000)...)
	if _, err := DecompressLZ4Block(nil, append(src, 0, 0x00), 1000); !errors.Is(err, ErrTooBig) {
		t.Errorf("lz4 match beyond maxOut: %v", err)
	}
	// LZO1X M3 with a huge extended length.
	src = append([]byte{18, 'a', 0x20}, bytes.Repeat([]byte{0}, 10000)...)
	src = append(src, 1, 0, 0, 0x11, 0, 0)
	if _, err := DecompressLZO1X(nil, src, 1<<20); !errors.Is(err, ErrTooBig) {
		t.Errorf("lzo match beyond maxOut: %v", err)
	}
	// The same as an end marker (M4, distance 0) decodes: only the
	// distance decides the end.
	src[2] = 0x10
	src = src[:len(src)-3]
	if got, err := DecompressLZO1X(nil, src, 10); err != nil || string(got) != "a" {
		t.Errorf("lzo end marker with a long length: %q, %v", got, err)
	}
}

// lz4Compress is a small greedy LZ4 block compressor for round trips. It
// keeps the format's end rules: the last 5 bytes are literals and the last
// match starts at least 12 bytes before the end.
func lz4Compress(src []byte) []byte {
	const minMatch, lastLiterals, mfLimit = 4, 5, 12
	var dst []byte
	table := map[uint32]int{}
	anchor := 0
	for i := 0; i+mfLimit <= len(src); {
		key := binary.LittleEndian.Uint32(src[i:])
		cand, seen := table[key]
		table[key] = i
		if !seen || i-cand > 65535 {
			i++
			continue
		}
		ml := minMatch
		for i+ml < len(src)-lastLiterals && src[cand+ml] == src[i+ml] {
			ml++
		}
		dst = lz4Sequence(dst, src[anchor:i], i-cand, ml)
		i += ml
		anchor = i
	}
	return lz4Sequence(dst, src[anchor:], 0, 0)
}

// lz4Sequence appends one sequence; off 0 means the literal-only last one.
func lz4Sequence(dst, lits []byte, off, ml int) []byte {
	token := byte(min(len(lits), 15)) << 4
	if off > 0 {
		token |= byte(min(ml-4, 15))
	}
	dst = append(dst, token)
	if len(lits) >= 15 {
		dst = lz4Ext(dst, len(lits)-15)
	}
	dst = append(dst, lits...)
	if off == 0 {
		return dst
	}
	dst = append(dst, byte(off), byte(off>>8))
	if ml-4 >= 15 {
		dst = lz4Ext(dst, ml-4-15)
	}
	return dst
}

func lz4Ext(dst []byte, n int) []byte {
	for ; n >= 255; n -= 255 {
		dst = append(dst, 255)
	}
	return append(dst, byte(n))
}

// roundTripInputs are varied deterministic inputs.
func roundTripInputs() [][]byte {
	r := rand.New(rand.NewPCG(1, 2))
	random := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	// Text-like: a small alphabet so matches of every length occur.
	alpha := func(n, k int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a' + byte(r.IntN(k))
		}
		return b
	}
	ins := [][]byte{
		{}, {0}, {0x50}, []byte("abc"), []byte("hello world!"), []byte("hello, world!"),
		bytes.Repeat([]byte{7}, 13), bytes.Repeat([]byte{7}, 100000),
		bytes.Repeat([]byte("ab"), 40), bytes.Repeat([]byte("0123456789abcdefg"), 300),
		random(1), random(16), random(1500), random(70000),
	}
	for n := 1; n <= 4096; n = n*2 + r.IntN(7) {
		ins = append(ins, alpha(n, 2), alpha(n, 4), alpha(n, 26), random(n))
	}
	// Repeats farther back than 64 KiB cannot be matched; repeats just
	// inside can.
	far := random(70000)
	far = append(far, far[:5000]...)
	far = append(far, far[len(far)-65535:len(far)-65535+100]...)
	return append(ins, far)
}

func TestLZ4RoundTrip(t *testing.T) {
	for _, in := range roundTripInputs() {
		c := lz4Compress(in)
		got, err := DecompressLZ4Block(nil, c, len(in))
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("%d-byte input (%d compressed): %d bytes, %v", len(in), len(c), len(got), err)
		}
		// Every strict prefix of the block either fails or yields a prefix
		// of the input; it never invents bytes.
		for _, n := range []int{0, 1, len(c) / 2, len(c) - 1} {
			if n < 0 || n >= len(c) {
				continue
			}
			got, err := DecompressLZ4Block(nil, c[:n], len(in))
			if err == nil && !bytes.HasPrefix(in, got) {
				t.Errorf("%d-byte input cut to %d: decoded bytes that are not a prefix", len(in), n)
			}
		}
	}
}

// Truncating any vector anywhere fails for LZO1X (the end marker is
// required), and for LZ4 fails or yields a strict prefix.
func TestTruncatedVectors(t *testing.T) {
	for _, v := range vectors(t).Vectors {
		for _, codec := range codecs {
			c := v.compressed(codec)
			step := max(1, len(c)/97)
			for n := 0; n < len(c); n += step {
				got, err := decoder(codec)(nil, c[:n], len(v.Input)+100)
				if err != nil {
					checkErr(t, v.Name+"/"+codec, err)
					continue
				}
				switch {
				case codec != "lz4":
					t.Errorf("%s/%s cut to %d of %d bytes: decoded %d bytes without error", v.Name, codec, n, len(c), len(got))
				case len(got) >= len(v.Input) || !bytes.HasPrefix(v.Input, got):
					t.Errorf("%s/%s cut to %d of %d bytes: %d bytes, not a strict prefix of the input", v.Name, codec, n, len(c), len(got))
				}
			}
		}
	}
}

func TestAppendMatchOverlap(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 2000 {
		seed := make([]byte, 1+r.IntN(40))
		for i := range seed {
			seed[i] = byte(r.Uint32())
		}
		dist := 1 + r.IntN(len(seed))
		n := r.IntN(300)
		s := newSink(slices.Clone(seed), n)
		s.base = 0
		if err := s.match(dist, n, errLZ4Distance); err != nil {
			t.Fatal(err)
		}
		want := slices.Clone(seed)
		for range n {
			want = append(want, want[len(want)-dist])
		}
		if !bytes.Equal(s.out, want) {
			t.Fatalf("match dist %d len %d after %d bytes: wrong output", dist, n, len(seed))
		}
	}
}

// Each mode's framing on the wire.
func TestFrameBytes(t *testing.T) {
	cases := []struct {
		mode    Mode
		payload string
		want    string
	}{
		{None, "\x45abc", "\x45abc"},
		{LZO, "\x45abc", "\xfa\x45abc"},
		{LZO, "\x50", "\xfa\x50"},
		{Swap, "\x45abc", "\xfbabc\x45"},
		{Swap, "\x45", "\xfb\x45"},
		{Swap, "\x45a", "\xfba\x45"},
		{V2, "\x45abc", "\x45abc"},
		{V2, "\x50abc", "\x50\x00\x50abc"},
		{V2, "\x50", "\x50\x00\x50"},
		{V2, "\xfa", "\xfa"},
		{Mode(42), "\x45", "\x45"},
		{None, "", ""}, {LZO, "", ""}, {Swap, "", ""}, {V2, "", ""},
	}
	for _, tc := range cases {
		got := Frame(tc.mode, nil, []byte(tc.payload))
		if string(got) != tc.want {
			t.Errorf("Frame(%v, %x) = %x, want %x", tc.mode, tc.payload, got, tc.want)
		}
		got = Frame(tc.mode, []byte("hdr"), []byte(tc.payload))
		if string(got) != "hdr"+tc.want {
			t.Errorf("Frame(%v, hdr, %x) = %x, want hdr then %x", tc.mode, tc.payload, got, tc.want)
		}
		// In place: the payload at the start of a buffer with spare room.
		buf := make([]byte, len(tc.payload), len(tc.payload)+2)
		copy(buf, tc.payload)
		got = Frame(tc.mode, buf[:0], buf)
		if string(got) != tc.want {
			t.Errorf("Frame(%v) in place = %x, want %x", tc.mode, got, tc.want)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	payloads := [][]byte{{}, {0x45}, {0x50}, {0x50, 0x00}, {0x50, 0x01}, {0xfa}, {0xfb}, {0x66}, {0x69}, {0x00}}
	for _, n := range []int{2, 3, 20, 1500, 65535} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(r.Uint32())
		}
		payloads = append(payloads, p)
		for _, first := range []byte{0x50, 0xfa, 0xfb, 0x66, 0x69, 0x45, 0x60} {
			q := slices.Clone(p)
			q[0] = first
			payloads = append(payloads, q)
		}
	}
	for _, m := range []Mode{None, LZO, Swap, V2} {
		for _, p := range payloads {
			framed := Frame(m, nil, p)
			got, err := Unframe(m, nil, slices.Clone(framed), 100)
			if err != nil || !bytes.Equal(got, p) {
				t.Errorf("%v: %d-byte payload %x...: got %d bytes, %v", m, len(p), p[:min(len(p), 2)], len(got), err)
			}
		}
	}
}

func TestUnframeAliases(t *testing.T) {
	p := []byte{0x45, 1, 2, 3}
	if got, _ := Unframe(V2, nil, p, 0); &got[0] != &p[0] || len(got) != 4 {
		t.Error("V2 without 0x50 does not return the payload itself")
	}
	if got, _ := Unframe(None, nil, p, 0); &got[0] != &p[0] {
		t.Error("None does not return the payload itself")
	}
	q := []byte{0xfa, 1, 2}
	if got, _ := Unframe(LZO, nil, q, 0); &got[0] != &q[1] {
		t.Error("LZO 0xfa does not return a subslice of the payload")
	}
	s := []byte{0xfb, 1, 2, 9}
	if got, _ := Unframe(Swap, nil, s, 0); &got[0] != &s[0] || !bytes.Equal(got, []byte{9, 1, 2}) {
		t.Errorf("Swap 0xfb: %x, want 090102 in place", got)
	}
	for _, m := range []Mode{None, LZO, Swap, V2} {
		got, err := Unframe(m, nil, []byte{}, 0)
		if err != nil || len(got) != 0 {
			t.Errorf("%v: empty payload: %x, %v", m, got, err)
		}
	}
}

// Compressed payloads in each framing, built from the reference vectors.
func TestUnframeCompressed(t *testing.T) {
	for _, v := range vectors(t).Vectors {
		lz := v.LZ4
		swapped := append([]byte{0x69}, lz[1:]...)
		swapped = append(swapped, lz[0])
		cases := []struct {
			name   string
			mode   Mode
			framed []byte
		}{
			{"lzo 0x66 lzo1x_1_15", LZO, append([]byte{0x66}, v.LZO1X1...)},
			{"lzo 0x66 lzo1x_999", LZO, append([]byte{0x66}, v.LZO1X999...)},
			{"swap 0x69 lz4", Swap, swapped},
			{"v2 0x50 0x01 lz4", V2, append([]byte{0x50, 0x01}, lz...)},
		}
		for _, tc := range cases {
			// dst with content before it: the result is the payload alone.
			dst := append(make([]byte, 0, 70000), "scratch"...)
			got, err := Unframe(tc.mode, dst, slices.Clone(tc.framed), len(v.Input))
			if err != nil || !bytes.Equal(got, v.Input) {
				t.Errorf("%s %s: got %d bytes, %v; want %d", v.Name, tc.name, len(got), err, len(v.Input))
			}
			if len(v.Input) > 0 {
				if _, err := Unframe(tc.mode, nil, slices.Clone(tc.framed), len(v.Input)-1); !errors.Is(err, ErrTooBig) {
					t.Errorf("%s %s with maxOut one short: %v, want ErrTooBig", v.Name, tc.name, err)
				}
			}
		}
	}
}

func TestUnframeErrors(t *testing.T) {
	for b := range 256 {
		p := []byte{byte(b), 1, 2, 3}
		_, err := Unframe(LZO, nil, slices.Clone(p), 100)
		if (b == 0xfa || b == 0x66) == errors.Is(err, ErrFraming) {
			t.Errorf("LZO flag 0x%02x: %v", b, err)
		}
		_, err = Unframe(Swap, nil, slices.Clone(p), 100)
		if (b == 0xfb || b == 0x69) == errors.Is(err, ErrFraming) {
			t.Errorf("Swap flag 0x%02x: %v", b, err)
		}
		got, err := Unframe(V2, nil, []byte{0x50, byte(b), 0x10, 'x'}, 100)
		switch b {
		case 0:
			if err != nil || string(got) != "\x10x" {
				t.Errorf("V2 0x50 0x00: %x, %v", got, err)
			}
		case 1:
			if err != nil || string(got) != "x" {
				t.Errorf("V2 0x50 0x01: %x, %v", got, err)
			}
		default:
			if !errors.Is(err, ErrFraming) {
				t.Errorf("V2 0x50 0x%02x: %v, want ErrFraming", b, err)
			}
		}
	}
	// An unknown flag leaves a swap-framed payload untouched.
	p := []byte{0x42, 1, 2, 3}
	if _, err := Unframe(Swap, nil, p, 100); !errors.Is(err, ErrFraming) || !bytes.Equal(p, []byte{0x42, 1, 2, 3}) {
		t.Errorf("swap unknown flag: %v, payload now %x", err, p)
	}
	if _, err := Unframe(V2, nil, []byte{0x50}, 100); !errors.Is(err, ErrFraming) {
		t.Errorf("V2 lone 0x50: %v", err)
	}
	if _, err := Unframe(Mode(7), nil, []byte{1}, 100); !errors.Is(err, ErrFraming) {
		t.Errorf("unknown mode: %v", err)
	}
	// A flag saying "compressed" with nothing after it.
	for _, tc := range []struct {
		m Mode
		p []byte
	}{{LZO, []byte{0x66}}, {Swap, []byte{0x69}}, {V2, []byte{0x50, 0x01}}} {
		if _, err := Unframe(tc.m, nil, tc.p, 100); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%v %x: %v, want ErrCorrupt", tc.m, tc.p, err)
		}
	}
	// Swap with a 1-byte payload: the flag alone.
	if got, err := Unframe(Swap, nil, []byte{0xfb}, 100); err != nil || len(got) != 0 {
		t.Errorf("swap 0xfb alone: %x, %v", got, err)
	}
	// Compressed and corrupt.
	if _, err := Unframe(LZO, nil, []byte{0x66, 0x40, 0x00, 0x11, 0, 0}, 100); !errors.Is(err, ErrCorrupt) {
		t.Errorf("lzo corrupt: %v", err)
	}
	if _, err := Unframe(V2, nil, []byte{0x50, 0x01, 0x14, 'a', 9, 0, 0}, 100); !errors.Is(err, ErrCorrupt) {
		t.Errorf("v2 lz4 corrupt: %v", err)
	}
}

func BenchmarkDecompressLZ4(b *testing.B) {
	v := benchVector(b)
	b.SetBytes(int64(len(v.Input)))
	dst := make([]byte, 0, len(v.Input))
	for b.Loop() {
		if _, err := DecompressLZ4Block(dst, v.LZ4, len(v.Input)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecompressLZO1X(b *testing.B) {
	v := benchVector(b)
	b.SetBytes(int64(len(v.Input)))
	dst := make([]byte, 0, len(v.Input))
	for b.Loop() {
		if _, err := DecompressLZO1X(dst, v.LZO1X1, len(v.Input)); err != nil {
			b.Fatal(err)
		}
	}
}

func benchVector(b *testing.B) *vector {
	for i, v := range vectors(b).Vectors {
		if v.Name == "mixed-64k" {
			return &vectors(b).Vectors[i]
		}
	}
	b.Fatal("no mixed-64k vector")
	return nil
}
