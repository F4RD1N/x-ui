package transport

// The server half of VPN-Core 0.12 transport/script.go (the TLS-shaped
// camouflage reply), kept for tests only.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
)

func nativeRandomBytes(r io.Reader, b []byte) error {
	// This differs from rand_buf: two initial words are discarded, and the final
	// partial eight-byte group comes from one pair of words, not per-byte draws.
	if _, err := randomWord(r); err != nil {
		return err
	}
	if _, err := randomWord(r); err != nil {
		return err
	}
	for len(b) > 0 {
		first, e := randomWord(r)
		if e != nil {
			return e
		}
		second, e := randomWord(r)
		if e != nil {
			return e
		}
		var pair [8]byte
		copy(pair[:], second[:])
		copy(pair[4:], first[:])
		n := copy(b, pair[:])
		b = b[n:]
	}
	return nil
}

// MakeCamouflageServerHello reproduces the native TLS-shaped prefix. It is
// deliberately not a TLS handshake: authentication happens in tunnel userinfo.
func MakeCamouflageServerHello(sessionID []byte, hybrid bool, r io.Reader) ([]byte, error) {
	if len(sessionID) > 32 {
		return nil, ErrScript
	}
	if r == nil {
		r = rand.Reader
	}
	w, err := randomWord(r)
	if err != nil {
		return nil, err
	}
	padding := int(binary.LittleEndian.Uint32(w[:])%200) + 512
	if !hybrid {
		w, err = randomWord(r)
		if err != nil {
			return nil, err
		}
		padding = int(binary.LittleEndian.Uint32(w[:])%200) + 1480
	}
	b := []byte{0x16, 3, 3, 0, 0, 2, 0, 0, 0, 3, 3}
	random32 := make([]byte, 32)
	if err = nativeRandomBytes(r, random32); err != nil {
		return nil, err
	}
	b = append(b, random32...)
	b = append(b, byte(len(sessionID)))
	b = append(b, sessionID...)
	b = append(b, 0x13, 1, 0)
	extensionLengthAt := len(b)
	b = append(b, 0, 0)
	shareLength := 32
	group := uint16(0x1d)
	if hybrid {
		shareLength = 1120
		group = 0x11ec
	}
	b = append(b, 0, 0x33)
	b = binary.BigEndian.AppendUint16(b, uint16(shareLength+4))
	b = binary.BigEndian.AppendUint16(b, group)
	b = binary.BigEndian.AppendUint16(b, uint16(shareLength))
	share := make([]byte, shareLength)
	if err = nativeRandomBytes(r, share); err != nil {
		return nil, err
	}
	b = append(b, share...)
	b = append(b, 0, 0x2b, 0, 2, 3, 4)
	binary.BigEndian.PutUint16(b[extensionLengthAt:], uint16(len(b)-extensionLengthAt-2))
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	hs := len(b) - 9
	b[6] = byte(hs >> 16)
	b[7] = byte(hs >> 8)
	b[8] = byte(hs)
	b = append(b, 0x14, 3, 3, 0, 1, 1, 0x17, 3, 3)
	b = binary.BigEndian.AppendUint16(b, uint16(padding))
	pad := make([]byte, padding)
	if err = nativeRandomBytes(r, pad); err != nil {
		return nil, err
	}
	return append(b, pad...), nil
}

func clientHelloSession(record []byte) (session []byte, hybrid bool, err error) {
	if len(record) < 59 || record[0] != 0x16 || record[1] != 3 || record[2] != 1 || record[5] != 1 || record[9] != 3 || record[10] != 3 {
		return nil, false, ErrScript
	}
	if int(binary.BigEndian.Uint16(record[3:5]))+5 != len(record) {
		return nil, false, ErrScript
	}
	hs := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if hs+9 != len(record) {
		return nil, false, ErrScript
	}
	n := int(record[43])
	if n > 32 || n > len(record)-44 {
		return nil, false, ErrScript
	}
	// Walk every length before touching it. The native probe walks ciphers,
	// compression and extension bodies too; accepting just the outer envelope
	// would respond to truncated or malformed ClientHello records.
	i := 44 + n
	if len(record)-i < 2 {
		return nil, false, ErrScript
	}
	cipherBytes := int(binary.BigEndian.Uint16(record[i:]))
	i += 2
	if cipherBytes > len(record)-i {
		return nil, false, ErrScript
	}
	i += cipherBytes
	if len(record)-i < 1 {
		return nil, false, ErrScript
	}
	compressionBytes := int(record[i])
	i++
	if compressionBytes > len(record)-i {
		return nil, false, ErrScript
	}
	i += compressionBytes
	if len(record)-i < 2 {
		return nil, false, ErrScript
	}
	extensionsBytes := int(binary.BigEndian.Uint16(record[i:]))
	i += 2
	// The reference walks the remaining record rather than enforcing this
	// advertised total. This implementation rejects that malformed mismatch.
	if extensionsBytes != len(record)-i {
		return nil, false, ErrScript
	}
	for i < len(record) {
		if len(record)-i < 4 {
			return nil, false, ErrScript
		}
		kind := binary.BigEndian.Uint16(record[i:])
		size := int(binary.BigEndian.Uint16(record[i+2:]))
		i += 4
		if size > len(record)-i || kind == 0 && size < 6 {
			return nil, false, ErrScript
		}
		i += size
	}
	session = append([]byte(nil), record[44:44+n]...)
	if n == 32 {
		random := record[11:43]
		if (random[0]^random[1])-0x5d == random[2] && (session[0]^session[1])+0x39 == session[2] && binary.LittleEndian.Uint32(random[6:10]) == crc32.ChecksumIEEE(random[:6]) {
			plain := append([]byte(nil), random[10:]...)
			for i := range plain {
				plain[i] ^= random[3+i%3]
			}
			if plain[0] == 0x6a {
				hybrid = binary.LittleEndian.Uint16(plain[2:4]) == 5
			}
		}
	}
	return session, hybrid, nil
}

func serveCamouflage(r io.Reader, w io.Writer, entropy io.Reader) error {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n < 54 || n > 4096 {
		return ErrScript
	}
	record := make([]byte, n+5)
	copy(record, h[:])
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		return err
	}
	session, hybrid, err := clientHelloSession(record)
	if err != nil {
		return err
	}
	hello, err := MakeCamouflageServerHello(session, hybrid, entropy)
	if err != nil {
		return err
	}
	_, err = writeFull(w, hello)
	return err
}

func isCamouflagePrefix(b []byte) bool { return bytes.Equal(b, []byte{0x16, 3, 1}) }
