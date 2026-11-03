package compress

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// addDecoderSeeds seeds f with the reference vectors and crafted streams of
// one codec ("lz4" or "lzo").
func addDecoderSeeds(f *testing.F, lib string) {
	vf := vectors(f)
	for _, v := range vf.Vectors {
		for _, codec := range codecs {
			c := v.compressed(codec)
			if (codec == "lz4") == (lib == "lz4") && len(c) <= 4096 {
				f.Add(c, uint16(len(v.Input)))
			}
		}
	}
	for _, c := range vf.Crafted {
		if c.Codec == lib {
			f.Add(c.Stream, uint16(c.Cap))
		}
	}
}

// checkDecoder checks the properties every decompressor must have on any
// input: no panic, only the documented errors, dst kept on error, never
// more than maxOut bytes, no dependence on dst's contents, and a success
// that repeats with maxOut set to exactly its size and fails one byte
// below.
func checkDecoder(t *testing.T, dec func(dst, src []byte, maxOut int) ([]byte, error), src []byte, maxOut int) []byte {
	prefix := []byte("prefix")
	out, err := dec(slices.Clone(prefix), src, maxOut)
	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("dst prefix not kept: %x", out[:min(len(out), 6)])
	}
	got := out[len(prefix):]
	plain, plainErr := dec(nil, src, maxOut)
	if (err == nil) != (plainErr == nil) || !bytes.Equal(got, plain) {
		t.Fatalf("result depends on dst: %v vs %v", err, plainErr)
	}
	if err != nil {
		if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTooBig) {
			t.Fatalf("undocumented error %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("error %v but %d bytes appended", err, len(got))
		}
		return nil
	}
	if len(got) > maxOut {
		t.Fatalf("%d bytes out, maxOut %d", len(got), maxOut)
	}
	again, err := dec(nil, src, len(got))
	if err != nil || !bytes.Equal(again, got) {
		t.Fatalf("maxOut = output size %d: %v", len(got), err)
	}
	if len(got) > 0 {
		if _, err := dec(nil, src, len(got)-1); !errors.Is(err, ErrTooBig) {
			t.Fatalf("maxOut one below output size: %v, want ErrTooBig", err)
		}
	}
	return got
}

func FuzzDecompressLZ4Block(f *testing.F) {
	addDecoderSeeds(f, "lz4")
	f.Fuzz(func(t *testing.T, src []byte, maxOut uint16) {
		out := checkDecoder(t, DecompressLZ4Block, src, int(maxOut))
		if out == nil {
			return
		}
		// Whatever decoded also survives our own compressor.
		got, err := DecompressLZ4Block(nil, lz4Compress(out), len(out))
		if err != nil || !bytes.Equal(got, out) {
			t.Fatalf("recompressed output: %v", err)
		}
	})
}

func FuzzDecompressLZO1X(f *testing.F) {
	addDecoderSeeds(f, "lzo")
	f.Fuzz(func(t *testing.T, src []byte, maxOut uint16) {
		checkDecoder(t, DecompressLZO1X, src, int(maxOut))
	})
}

func FuzzLZ4RoundTrip(f *testing.F) {
	for _, in := range roundTripInputs() {
		if len(in) <= 4096 {
			f.Add(in)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c := lz4Compress(in)
		got, err := DecompressLZ4Block(nil, c, len(in))
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("%d bytes, %d compressed: %v", len(in), len(c), err)
		}
	})
}

func FuzzUnframe(f *testing.F) {
	for _, v := range vectors(f).Vectors {
		if len(v.LZ4) > 2048 || len(v.LZO1X1) > 2048 {
			continue
		}
		swapped := append([]byte{0x69}, v.LZ4[1:]...)
		f.Add(uint8(LZO), append([]byte{0x66}, v.LZO1X1...), uint16(len(v.Input)))
		f.Add(uint8(Swap), append(swapped, v.LZ4[0]), uint16(len(v.Input)))
		f.Add(uint8(V2), append([]byte{0x50, 0x01}, v.LZ4...), uint16(len(v.Input)))
	}
	for _, p := range [][]byte{{}, {0xfa}, {0xfb}, {0x50}, {0x50, 0}, {0x50, 2}, {0xfb, 1, 2}, {0x45, 0, 0, 0}} {
		for m := range 5 {
			f.Add(uint8(m), p, uint16(100))
		}
	}
	f.Fuzz(func(t *testing.T, mode uint8, payload []byte, maxOut uint16) {
		m := Mode(mode % 5) // 4 is no mode
		in := slices.Clone(payload)
		got, err := Unframe(m, []byte("scratch")[:0], in, int(maxOut))
		if err != nil {
			if !errors.Is(err, ErrFraming) && !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTooBig) {
				t.Fatalf("undocumented error %v", err)
			}
		} else if len(got) > max(len(payload), int(maxOut)) {
			t.Fatalf("%d bytes from a %d-byte payload with maxOut %d", len(got), len(payload), maxOut)
		}
		if m == Mode(4) {
			return
		}
		framed := Frame(m, nil, payload)
		back, err := Unframe(m, nil, framed, 0)
		if err != nil || !bytes.Equal(back, payload) {
			t.Fatalf("%v round trip of %x: %x, %v", m, payload, back, err)
		}
	})
}
