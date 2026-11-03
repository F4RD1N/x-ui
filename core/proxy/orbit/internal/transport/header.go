// Package transport implements the recovered reference stream wrappers.
// Its header-derived AES stream is obfuscation, not an authentication boundary.
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

var (
	ErrHeader      = errors.New("transport: no valid obfuscation header within scan limit")
	ErrProxyBuffer = errors.New("transport: proxy buffer exceeds configured limit")
)

// MakeHeader duplicates the original random-word consumption and header layout.
// A nil source selects crypto/rand; a deterministic source is useful for vectors.
func MakeHeader(source io.Reader) ([]byte, [16]byte, error) {
	if source == nil {
		source = rand.Reader
	}
	var word [4]byte
	if _, err := io.ReadFull(source, word[:]); err != nil {
		return nil, [16]byte{}, err
	}
	third := (word[0] ^ word[1]) + 0x75
	n := int(third%6) + 10
	// The native builder writes extra random words, though only n bytes are sent.
	buf := make([]byte, 3+4*(n-7))
	copy(buf, word[:])
	buf[2] = third
	if _, err := io.ReadFull(source, buf[3:]); err != nil {
		return nil, [16]byte{}, err
	}
	buf = buf[:n]
	binary.LittleEndian.PutUint32(buf[n-4:], crc32.ChecksumIEEE(buf[:n-4])+0x2f4d)
	return buf, md5.Sum(buf), nil
}

// FindHeader finds the first complete CRC-valid header. consumed is either the
// number through that header, or the safe prefix to discard awaiting more bytes.
func FindHeader(data []byte) (consumed int, key [16]byte, found bool) {
	incomplete := -1
	for len(data)-consumed >= 3 {
		b := data[consumed:]
		if (b[0]^b[1])+0x75 != b[2] {
			consumed++
			continue
		}
		n := int(b[2]%6) + 10
		if len(b) < n {
			// Prefix noise can resemble a longer header and overlap a complete
			// shorter header. Stopping here would wait for bytes the peer sends
			// only after this handshake. Keep the candidate for fragmentation,
			// but also inspect later positions for an already complete header.
			if incomplete < 0 {
				incomplete = consumed
			}
			consumed++
			continue
		}
		if binary.LittleEndian.Uint32(b[n-4:n]) != crc32.ChecksumIEEE(b[:n-4])+0x2f4d {
			consumed++
			continue
		}
		return consumed + n, md5.Sum(b[:n]), true
	}
	if incomplete >= 0 {
		consumed = incomplete
	}
	return consumed, key, false
}

func ctr(key [16]byte) cipher.Stream {
	block, _ := aes.NewCipher(key[:]) // A 16-byte key is always accepted.
	return cipher.NewCTR(block, key[:])
}
