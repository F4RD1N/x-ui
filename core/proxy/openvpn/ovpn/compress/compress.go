// Package compress handles OpenVPN's data-channel compression framing. The
// client never compresses (like OpenVPN 2.6's "asym" mode) but must frame
// what it sends the way the peer expects and must undo the peer's framing,
// decompressing when an older peer did compress.
//
// Framings (first byte of the decrypted payload):
//
//	LZO  (comp-lzo yes|no|adaptive, compress lzo):
//	     0xFA = not compressed, payload follows; 0x66 = LZO1X data follows.
//	     Send: prefix 0xFA.
//	Swap (compress, compress stub, compress lz4):
//	     the flag byte replaces the payload's first byte, which is moved to
//	     the end. 0xFB = not compressed; 0x69 = LZ4 block. Receive: take the
//	     flag, put the last byte back in front, drop the last byte; then
//	     LZ4-decompress if the flag was 0x69.
//	     Send: move the first byte to the end, write 0xFB in its place.
//	V2   (compress stub-v2, compress lz4-v2):
//	     no framing unless the first byte is 0x50; then the second byte says
//	     0 = not compressed, 1 = LZ4 block, and both are stripped.
//	     Send: only a payload starting with 0x50 gets "0x50 0x00" prefixed.
//	None: no framing.
//
// An empty payload is never framed, in either direction, as OpenVPN does.
//
// LZ4 is the raw block format (no frame header). LZO is LZO1X as written by
// lzo1x_1_15_compress, read like lzo1x_decompress_safe.
//
// The decompressors take untrusted input: every length and distance is
// checked against the input, the output produced so far and maxOut, and bad
// data yields ErrCorrupt or ErrTooBig, never a panic.
package compress

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// Mode is the framing negotiated for the data channel.
type Mode int

const (
	None Mode = iota
	LZO
	Swap
	V2
)

var (
	ErrFraming = errors.New("compress: bad framing byte")
	ErrCorrupt = errors.New("compress: corrupt compressed data")
	ErrTooBig  = errors.New("compress: decompressed data exceeds limit")
)

// Flag bytes on the wire.
const (
	lzoPlain       = 0xFA // LZO framing: not compressed
	lzoCompressed  = 0x66 // LZO framing: LZO1X data follows
	swapPlain      = 0xFB // swap framing: not compressed
	swapLZ4        = 0x69 // swap framing: LZ4 block
	v2Indicator    = 0x50 // V2 framing: a second byte follows
	v2Uncompressed = 0x00
	v2LZ4          = 0x01
)

// ParseCompLZO maps a --comp-lzo argument ("", yes, no, adaptive) to its
// Mode, which is always LZO.
func ParseCompLZO(arg string) (Mode, error) {
	switch arg {
	case "", "yes", "no", "adaptive":
		return LZO, nil
	}
	return None, fmt.Errorf("compress: unknown comp-lzo argument %q (want yes, no or adaptive)", arg)
}

// ParseCompress maps a --compress argument ("", stub, stub-v2, lzo, lz4,
// lz4-v2, migrate) to its Mode. "migrate" is a server setting; for a client
// it means None.
func ParseCompress(arg string) (Mode, error) {
	switch arg {
	case "", "stub", "lz4":
		return Swap, nil
	case "stub-v2", "lz4-v2":
		return V2, nil
	case "lzo":
		return LZO, nil
	case "migrate":
		return None, nil
	}
	return None, fmt.Errorf("compress: unknown compress algorithm %q (want stub, stub-v2, lzo, lz4, lz4-v2 or migrate)", arg)
}

// String names the mode for logs.
func (m Mode) String() string {
	switch m {
	case None:
		return "none"
	case LZO:
		return "lzo"
	case Swap:
		return "swap"
	case V2:
		return "v2"
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

// Frame appends payload framed as "not compressed" for mode m to dst.
//
// An empty payload appends nothing; an unknown mode frames like None.
// payload may overlap the spare capacity of dst: Frame(m, p[:0], p) frames
// p in place when cap(p) leaves room for the one or two framing bytes.
func Frame(m Mode, dst, payload []byte) []byte {
	n := len(payload)
	if n == 0 {
		return dst
	}
	// Every read of payload happens before the framing bytes are written,
	// and copy has memmove semantics, so overlapping buffers are safe.
	switch m {
	case LZO:
		dst, tail := extend(dst, n+1)
		copy(tail[1:], payload)
		tail[0] = lzoPlain
		return dst
	case Swap:
		first := payload[0]
		dst, tail := extend(dst, n+1)
		copy(tail[1:n], payload[1:])
		tail[n] = first
		tail[0] = swapPlain
		return dst
	case V2:
		if payload[0] != v2Indicator {
			return append(dst, payload...)
		}
		dst, tail := extend(dst, n+2)
		copy(tail[2:], payload)
		tail[0], tail[1] = v2Indicator, v2Uncompressed
		return dst
	}
	return append(dst, payload...)
}

// extend lengthens dst by n bytes and returns it with the new part.
func extend(dst []byte, n int) (all, tail []byte) {
	l := len(dst)
	dst = slices.Grow(dst, n)[:l+n]
	return dst, dst[l:]
}

// Unframe removes mode m's framing from payload, decompressing into dst if
// the peer compressed. maxOut bounds the decompressed size. The result may
// alias payload when nothing had to be decompressed.
//
// The result is the payload alone: decompressed bytes are appended to dst
// (which must not overlap payload) and the result covers just them, so pass
// a scratch buffer as dst[:0]. Swap framing is undone in place, so payload
// is modified, also when the decompression that follows fails. Unknown flag
// bytes, a lone 0x50 in V2 and an unknown mode give ErrFraming; bad
// compressed data gives ErrCorrupt or ErrTooBig. An empty payload is
// returned as it is.
func Unframe(m Mode, dst, payload []byte, maxOut int) ([]byte, error) {
	if m == None {
		return payload, nil
	}
	if m != LZO && m != Swap && m != V2 {
		return nil, fmt.Errorf("%w: unknown mode %d", ErrFraming, int(m))
	}
	if len(payload) == 0 {
		return payload, nil
	}
	flag := payload[0]
	switch m {
	case LZO:
		switch flag {
		case lzoPlain:
			return payload[1:], nil
		case lzoCompressed:
			return decompress(DecompressLZO1X, dst, payload[1:], maxOut)
		}
		return nil, fmt.Errorf("%w: 0x%02x in lzo framing (want 0xfa or 0x66)", ErrFraming, flag)
	case Swap:
		if flag != swapPlain && flag != swapLZ4 {
			return nil, fmt.Errorf("%w: 0x%02x in swap framing (want 0xfb or 0x69)", ErrFraming, flag)
		}
		last := len(payload) - 1
		payload[0] = payload[last]
		body := payload[:last]
		if flag == swapPlain {
			return body, nil
		}
		return decompress(DecompressLZ4Block, dst, body, maxOut)
	default: // V2
		if flag != v2Indicator {
			return payload, nil
		}
		if len(payload) < 2 {
			return nil, fmt.Errorf("%w: v2 framing byte 0x50 without an algorithm byte", ErrFraming)
		}
		switch payload[1] {
		case v2Uncompressed:
			return payload[2:], nil
		case v2LZ4:
			return decompress(DecompressLZ4Block, dst, payload[2:], maxOut)
		}
		return nil, fmt.Errorf("%w: v2 algorithm byte 0x%02x (want 0 or 1)", ErrFraming, payload[1])
	}
}

// decompress runs fn and returns only what it appended to dst.
func decompress(fn func(dst, src []byte, maxOut int) ([]byte, error), dst, src []byte, maxOut int) ([]byte, error) {
	base := len(dst)
	out, err := fn(dst, src, maxOut)
	if err != nil {
		return nil, err
	}
	return out[base:], nil
}

// Decoder errors. They wrap ErrCorrupt and are static so that a peer
// sending garbage costs no allocation.
var (
	errLZ4Empty      = fmt.Errorf("%w: empty lz4 block", ErrCorrupt)
	errLZ4Truncated  = fmt.Errorf("%w: lz4 block ends inside a sequence", ErrCorrupt)
	errLZ4ZeroOffset = fmt.Errorf("%w: lz4 match offset 0", ErrCorrupt)
	errLZ4Distance   = fmt.Errorf("%w: lz4 match reaches before the start of the output", ErrCorrupt)
	errLZOEmpty      = fmt.Errorf("%w: empty lzo1x stream", ErrCorrupt)
	errLZOTruncated  = fmt.Errorf("%w: lzo1x stream ends before its end-of-stream marker", ErrCorrupt)
	errLZODistance   = fmt.Errorf("%w: lzo1x match reaches before the start of the output", ErrCorrupt)
	errLZOTrailing   = fmt.Errorf("%w: lzo1x data after the end-of-stream marker", ErrCorrupt)
	errLZOLength     = fmt.Errorf("%w: lzo1x length field too large", ErrCorrupt)
)

// maxRun bounds an LZO1X length before it is compared with maxOut, so that
// summing a long run of zero extension bytes cannot overflow a 32-bit int.
const maxRun = 1 << 30

// sink collects decompressed bytes after the caller's dst.
type sink struct {
	out  []byte
	base int // len(dst): matches may not reach before it
	room int // bytes that may still be appended
}

func newSink(dst []byte, maxOut int) sink {
	return sink{out: dst, base: len(dst), room: max(maxOut, 0)}
}

// literals appends n bytes of src starting at i and returns the index after
// them.
func (s *sink) literals(src []byte, i, n int, truncated error) (int, error) {
	if n > len(src)-i {
		return i, truncated
	}
	if n > s.room {
		return i, ErrTooBig
	}
	s.out = append(s.out, src[i:i+n]...)
	s.room -= n
	return i + n, nil
}

// match appends n bytes copied from dist bytes back. The two may overlap
// (dist < n), which repeats the last dist bytes; dist must be at least 1.
func (s *sink) match(dist, n int, behind error) error {
	if dist > len(s.out)-s.base || dist < 1 {
		return behind
	}
	if n > s.room {
		return ErrTooBig
	}
	s.room -= n
	start := len(s.out) - dist
	if dist >= n {
		s.out = append(s.out, s.out[start:start+n]...)
		return nil
	}
	pos := len(s.out)
	s.out = slices.Grow(s.out, n)[:pos+n]
	// The output from start on repeats with period dist. Copy it forward in
	// chunks that double in size; each ends on a multiple of dist, so the
	// next chunk again starts in phase.
	for done := 0; done < n; {
		done += copy(s.out[pos+done:pos+n], s.out[start:pos+done])
	}
	return nil
}

// DecompressLZ4Block appends the decompression of one raw LZ4 block to dst.
//
// A block is a run of sequences: a token (literal count in the high nibble,
// match length minus 4 in the low one, 15 meaning extension bytes follow,
// each adding its value and 255 continuing), the literals, a little-endian
// 16-bit match offset and the match length's extension bytes. The last
// sequence stops after its literals, at the end of src. Matches may not
// reach into dst's original contents, and offset 0 is rejected as the
// format requires (liblz4 1.9.4 writes zeros for it). Apart from that the
// decoder accepts every block LZ4_decompress_safe accepts, with the same
// output; it skips that function's end-of-block parsing restrictions, so it
// also decodes a few malformed blocks that liblz4 refuses.
//
// At most maxOut bytes are appended (ErrTooBig past that). On error dst is
// returned with its original length.
func DecompressLZ4Block(dst, src []byte, maxOut int) ([]byte, error) {
	if len(src) == 0 {
		return dst, errLZ4Empty
	}
	s := newSink(dst, maxOut)
	i := 0
	for {
		if i >= len(src) {
			// The previous sequence ended with a match: the block has no
			// final literals.
			return dst, errLZ4Truncated
		}
		token := src[i]
		i++

		lit := int(token >> 4)
		if lit == 15 {
			var err error
			// Literals come from src, so their count is bounded by it.
			if lit, i, err = lz4Length(src, i, lit, len(src), errLZ4Truncated); err != nil {
				return dst, err
			}
		}
		var err error
		if i, err = s.literals(src, i, lit, errLZ4Truncated); err != nil {
			return dst, err
		}
		if i == len(src) {
			return s.out, nil
		}

		if len(src)-i < 2 {
			return dst, errLZ4Truncated
		}
		off := int(src[i]) | int(src[i+1])<<8
		i += 2
		if off == 0 {
			return dst, errLZ4ZeroOffset
		}
		ml := int(token & 15)
		if ml == 15 {
			if ml, i, err = lz4Length(src, i, ml, s.room, ErrTooBig); err != nil {
				return dst, err
			}
		}
		if ml > s.room-4 {
			return dst, ErrTooBig
		}
		if err := s.match(off, ml+4, errLZ4Distance); err != nil {
			return dst, err
		}
	}
}

// lz4Length adds the extension bytes at src[i:] to n (each byte adds its
// value; 255 means another byte follows). It fails with tooLong once n would
// exceed limit, before any overflow.
func lz4Length(src []byte, i, n, limit int, tooLong error) (int, int, error) {
	for {
		if i >= len(src) {
			return 0, i, errLZ4Truncated
		}
		b := int(src[i])
		i++
		if b > limit-n {
			return 0, i, tooLong
		}
		n += b
		if b != 255 {
			return n, i, nil
		}
	}
}

// DecompressLZO1X appends the decompression of LZO1X data to dst.
//
// The stream is a series of instructions. Each one's low two bits (of the
// instruction byte, or of the first distance byte for M3/M4) count the
// literals (0-3) copied right after it, and what an instruction byte below
// 16 means depends on how many literals came just before it:
//
//	first byte 18..255  copy byte-17 literals; the next instruction reads
//	          them as 1-3 literals or as a run of 4 or more
//	first byte 0..17    an ordinary instruction (11 00 00 alone: no data)
//	0000LLLL  after a match with no literals: copy 3+L literals (L=0: 18 +
//	          255 per zero byte + the first non-zero byte)
//	0000DDSS HHHHHHHH  after 1-3 literals (M1): copy 2 bytes from
//	          1+D+4H back
//	0000DDSS HHHHHHHH  after a run of 4 or more literals: copy 3 bytes from
//	          2049+D+4H back
//	01LDDDSS HHHHHHHH  (M2) copy 3+L bytes from 1+D+8H back
//	1LLDDDSS HHHHHHHH  (M2) copy 5+L bytes from 1+D+8H back
//	001LLLLL [ext] DDDDDDSS DDDDDDDD  (M3) copy 2+L bytes (L=0: 33 + ext)
//	          from 1+D back, D the 14-bit little-endian value
//	0001HLLL [ext] DDDDDDSS DDDDDDDD  (M4) copy 2+L bytes (L=0: 9 + ext)
//	          from 16384+16384H+D back; H=0, D=0 ends the stream
//
// The end marker must be the last thing in src, as lzo1x_decompress_safe
// requires. Matches may not reach into dst's original contents. At most
// maxOut bytes are appended (ErrTooBig past that). On error dst is returned
// with its original length.
func DecompressLZO1X(dst, src []byte, maxOut int) ([]byte, error) {
	if len(src) == 0 {
		return dst, errLZOEmpty
	}
	s := newSink(dst, maxOut)
	i := 0
	// state is the number of literals the previous instruction copied: 0,
	// 1-3, or 4 for a run of four or more.
	state := 0
	var err error
	if src[0] > 17 {
		n := int(src[0]) - 17
		if i, err = s.literals(src, 1, n, errLZOTruncated); err != nil {
			return dst, err
		}
		state = min(n, 4)
	}
	for {
		if i >= len(src) {
			return dst, errLZOTruncated
		}
		t := int(src[i])
		i++

		var dist, length, trailing int
		switch {
		case t >= 64: // M2
			if i >= len(src) {
				return dst, errLZOTruncated
			}
			length = t>>5 + 1
			dist = 1 + (t>>2)&7 + int(src[i])<<3
			trailing = t & 3
			i++

		case t >= 16: // M3 (32..63) or M4 (16..31)
			mask, extBase := 7, 9
			if t >= 32 {
				mask, extBase = 31, 33
			}
			length = 2 + t&mask
			if t&mask == 0 {
				if length, i, err = lzoLength(src, i, extBase); err != nil {
					return dst, err
				}
			}
			if len(src)-i < 2 {
				return dst, errLZOTruncated
			}
			d := (int(src[i]) | int(src[i+1])<<8) >> 2
			trailing = int(src[i]) & 3
			i += 2
			if t >= 32 {
				dist = 1 + d
			} else {
				dist = (t&8)<<11 + d
				if dist == 0 {
					if i != len(src) {
						return dst, errLZOTrailing
					}
					return s.out, nil
				}
				dist += 16384
			}

		case state == 0: // a run of four or more literals
			n := 3 + t
			if t == 0 {
				if n, i, err = lzoLength(src, i, 18); err != nil {
					return dst, err
				}
			}
			if i, err = s.literals(src, i, n, errLZOTruncated); err != nil {
				return dst, err
			}
			state = 4
			continue

		default: // M1 after 1-3 literals, or the 3-byte copy after a run
			if i >= len(src) {
				return dst, errLZOTruncated
			}
			length, dist = 2, 1
			if state == 4 {
				length, dist = 3, 2049
			}
			dist += t>>2 + int(src[i])<<2
			trailing = t & 3
			i++
		}

		if err := s.match(dist, length, errLZODistance); err != nil {
			return dst, err
		}
		if trailing > 0 {
			if i, err = s.literals(src, i, trailing, errLZOTruncated); err != nil {
				return dst, err
			}
		}
		state = trailing
	}
}

// lzoLength reads an LZO1X length extension at src[i:]: 255 for each zero
// byte, then the first non-zero byte, all added to base.
func lzoLength(src []byte, i, base int) (int, int, error) {
	n := base
	for {
		if i >= len(src) {
			return 0, i, errLZOTruncated
		}
		b := int(src[i])
		i++
		if b != 0 {
			return n + b, i, nil
		}
		if n += 255; n > maxRun {
			return 0, i, errLZOLength
		}
	}
}
