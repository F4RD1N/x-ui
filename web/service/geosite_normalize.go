package service

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mhsanaei/3x-ui/v2/logger"
)

// NormalizeGeositeCountryCodes uppercases the country_code of every entry in
// a geosite .dat file. This works around a case-sensitivity mismatch in
// Xray-core: the router normalizes codes to uppercase before lookup, but the
// find() function compares bytes case-sensitively. Some geosite.dat providers
// (e.g. Loyalsoldier) store codes in lowercase, causing lookup failures.
//
// The file is read as a stream and only the code bytes are rewritten, in
// place: an uppercase code has the same length, so nothing else moves. Parsing
// the whole list instead (proto.Unmarshal) took about 7 times the file's size
// in memory on every panel start -- some 500 MB for a 74 MB geosite_RU.dat --
// and Go kept it, so the panel held most of a small server's RAM. Only ASCII
// letters are changed; country codes are ASCII.
func NormalizeGeositeCountryCodes(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to read geosite file %s: %w", path, err)
	}
	defer f.Close()

	// The whole file is checked before anything is written, so a damaged
	// file is reported and left as it was.
	codes, entries, err := lowercaseGeositeCodes(bufio.NewReaderSize(f, 64<<10))
	if err != nil {
		return fmt.Errorf("failed to parse geosite file %s: %w", path, err)
	}
	if len(codes) == 0 {
		return nil
	}
	for _, c := range codes {
		if _, err := f.WriteAt(asciiUpper(c.code), c.offset); err != nil {
			return fmt.Errorf("failed to write normalized geosite file %s: %w", path, err)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to write normalized geosite file %s: %w", path, err)
	}

	logger.Infof("Normalized country codes to uppercase in %s (%d of %d entries)", path, len(codes), entries)
	return nil
}

// geositeCode is a country_code with a lowercase letter: its bytes and where
// they start in the file.
type geositeCode struct {
	offset int64
	code   []byte
}

// protobuf wire types (https://protobuf.dev/programming-guides/encoding/)
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

// lowercaseGeositeCodes walks a GeoSiteList in protobuf wire format
// (GeoSiteList { repeated GeoSite entry = 1 }, GeoSite { string country_code = 1;
// repeated Domain domain = 2 }) and returns the country codes that contain a
// lowercase ASCII letter, and the number of entries. Domains and any other
// field are skipped without being read into memory.
func lowercaseGeositeCodes(br *bufio.Reader) ([]geositeCode, int, error) {
	r := &wireReader{r: br}
	var codes []geositeCode
	entries := 0
	for {
		tag, err := r.uvarint()
		if errors.Is(err, io.EOF) && r.n == r.tagStart {
			return codes, entries, nil // the end of the file, between fields
		}
		if err != nil {
			return nil, 0, err
		}
		if tag>>3 != 1 || tag&7 != wireLen {
			if err := r.skip(tag&7, -1); err != nil {
				return nil, 0, err
			}
			continue
		}
		size, err := r.uvarint()
		if err != nil {
			return nil, 0, err
		}
		end := r.n + int64(size)
		if size > 1<<40 || end < r.n {
			return nil, 0, fmt.Errorf("entry at %d: bad length %d", r.n, size)
		}
		entries++
		for r.n < end {
			ftag, err := r.uvarint()
			if err != nil {
				return nil, 0, err
			}
			if ftag>>3 == 1 && ftag&7 == wireLen {
				n, err := r.uvarint()
				if err != nil {
					return nil, 0, err
				}
				if n > 1<<16 || r.n+int64(n) > end {
					return nil, 0, fmt.Errorf("entry at %d: country code of %d bytes", r.n, n)
				}
				at := r.n
				code, err := r.bytes(int(n))
				if err != nil {
					return nil, 0, err
				}
				if hasASCIILower(code) {
					codes = append(codes, geositeCode{offset: at, code: code})
				}
				continue
			}
			if err := r.skip(ftag&7, end); err != nil {
				return nil, 0, err
			}
		}
		if r.n != end {
			return nil, 0, fmt.Errorf("entry ends at %d, not at %d", r.n, end)
		}
	}
}

// wireReader reads protobuf wire data and counts the bytes it has used.
type wireReader struct {
	r        *bufio.Reader
	n        int64 // bytes read so far
	tagStart int64 // where the last uvarint began
}

func (w *wireReader) ReadByte() (byte, error) {
	b, err := w.r.ReadByte()
	if err == nil {
		w.n++
	}
	return b, err
}

func (w *wireReader) uvarint() (uint64, error) {
	w.tagStart = w.n
	v, err := binary.ReadUvarint(w)
	if err != nil && w.n != w.tagStart && errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF // the file ends inside a number
	}
	return v, err
}

func (w *wireReader) bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(w.r, b); err != nil {
		return nil, unexpected(err)
	}
	w.n += int64(n)
	return b, nil
}

func (w *wireReader) discard(n uint64) error {
	for n > 0 {
		step := n
		if step > 1<<30 {
			step = 1 << 30
		}
		got, err := w.r.Discard(int(step))
		w.n += int64(got)
		if err != nil {
			return unexpected(err)
		}
		n -= step
	}
	return nil
}

// skip passes over one field's value of wire type wt, which must end by end
// (-1: anywhere).
func (w *wireReader) skip(wt uint64, end int64) error {
	switch wt {
	case wireVarint:
		if _, err := w.uvarint(); err != nil {
			return unexpected(err)
		}
	case wireI64:
		if err := w.discard(8); err != nil {
			return err
		}
	case wireI32:
		if err := w.discard(4); err != nil {
			return err
		}
	case wireLen:
		n, err := w.uvarint()
		if err != nil {
			return unexpected(err)
		}
		if n > 1<<40 || (end >= 0 && w.n+int64(n) > end) {
			return fmt.Errorf("field at %d: bad length %d", w.n, n)
		}
		if err := w.discard(n); err != nil {
			return err
		}
	default:
		return fmt.Errorf("field at %d: unsupported wire type %d", w.n, wt)
	}
	if end >= 0 && w.n > end {
		return fmt.Errorf("field at %d runs past its entry's end %d", w.n, end)
	}
	return nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func hasASCIILower(b []byte) bool {
	for _, c := range b {
		if 'a' <= c && c <= 'z' {
			return true
		}
	}
	return false
}

func asciiUpper(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
