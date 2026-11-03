package transport

import (
	"bufio"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Options describes the recovered obfuscation profile. ProxyBuffer is opaque
// route metadata; the server returns it to the channel/relay policy layer.
type Options struct {
	ProxyBuffer   []byte
	Random        io.Reader
	Timeout       time.Duration
	MaxScanBytes  int
	MaxProxyBytes int
	// Script is the exact binary route-supplied client segment program of a
	// provider route with TCP selector 4 (VPN-Core 0.12). Orbit never sets it.
	Script []byte
	plain  bool
}

func (o Options) normalized() (Options, error) {
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxScanBytes == 0 {
		o.MaxScanBytes = 4096
	}
	if o.MaxProxyBytes == 0 {
		o.MaxProxyBytes = 65535
	}
	if o.Timeout < 0 || o.MaxScanBytes < 15 || o.MaxScanBytes > 1<<20 || o.MaxProxyBytes < 0 || o.MaxProxyBytes > 65535 {
		return o, errors.New("transport: invalid handshake options")
	}
	if len(o.ProxyBuffer) > o.MaxProxyBytes {
		return o, ErrProxyBuffer
	}
	return o, nil
}

// Conn preserves independent continuous AES-CTR state for each direction and
// serializes concurrent callers, as required by net.Conn's contract.
type Conn struct {
	net.Conn
	reader                  *bufio.Reader
	readCipher, writeCipher cipher.Stream
	readMu, writeMu         sync.Mutex
	writeErr                error
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.reader.Read(p)
	if n > 0 && c.readCipher != nil {
		c.readCipher.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 32*1024 {
			n = 32 * 1024
		}
		buf := make([]byte, n)
		if c.writeCipher != nil {
			c.writeCipher.XORKeyStream(buf, p[:n])
		} else {
			copy(buf, p[:n])
		}
		m, err := writeFull(c.Conn, buf)
		written += m
		if err != nil {
			// The keystream has advanced. Close rather than silently desynchronize
			// a caller that retries a partial encrypted write after a timeout.
			c.writeErr = err
			_ = c.Conn.Close()
			return written, err
		}
		p = p[n:]
	}
	return written, nil
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("transport: underlying connection cannot half-close")
}

func writeFull(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return total, errors.New("transport: invalid writer count")
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func readHeader(r *bufio.Reader, limit int) ([16]byte, error) {
	buf := make([]byte, 0, 15)
	for total := 0; total < limit; total++ {
		b, err := r.ReadByte()
		if err != nil {
			return [16]byte{}, err
		}
		buf = append(buf, b)
		consumed, key, found := FindHeader(buf)
		if found {
			return key, nil
		}
		if consumed > 0 {
			copy(buf, buf[consumed:])
			buf = buf[:len(buf)-consumed]
		}
	}
	return [16]byte{}, ErrHeader
}

// handshakeLifetime bounds time even while the peer is silent. Cancellation
// closes the connection. A completed handshake transfers ownership to Conn;
// later context cancellation no longer changes that connection's lifetime.
func handshakeLifetime(ctx context.Context, c net.Conn, timeout time.Duration) (func(bool) error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); close(finished) })
	return func(success bool) error {
		if !stop() {
			<-finished
		}
		if err := ctx.Err(); err != nil {
			_ = c.Close()
			return err
		}
		if !success {
			_ = c.Close()
			return nil
		}
		return c.SetDeadline(time.Time{})
	}, nil
}

// Client performs the recovered client header + encrypted LE16 proxy buffer
// exchange (TCP selector 4), then reads the server's independent header. A
// route script runs first. It owns raw on failure.
func Client(ctx context.Context, raw net.Conn, options Options) (result *Conn, err error) {
	o, err := options.normalized()
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	finish, err := handshakeLifetime(ctx, raw, o.Timeout)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer func() {
		if e := finish(err == nil); e != nil {
			err = e
			result = nil
		}
	}()
	return clientHandshake(ctx, raw, o)
}

func clientHandshake(ctx context.Context, raw net.Conn, o Options) (*Conn, error) {
	if len(o.Script) > 0 {
		script, e := ParseScript(o.Script)
		if e != nil {
			return nil, e
		}
		if e = executeScript(ctx, raw, script); e != nil {
			return nil, e
		}
	}
	header, key, err := MakeHeader(o.Random)
	if err != nil {
		return nil, err
	}
	enc := ctr(key)
	proxy := make([]byte, 2+len(o.ProxyBuffer))
	binary.LittleEndian.PutUint16(proxy, uint16(len(o.ProxyBuffer)))
	copy(proxy[2:], o.ProxyBuffer)
	if !o.plain {
		enc.XORKeyStream(proxy, proxy)
	}
	if _, err = writeFull(raw, append(header, proxy...)); err != nil {
		return nil, fmt.Errorf("transport client preface: %w", err)
	}
	r := bufio.NewReaderSize(raw, 4096)
	peerKey, err := readHeader(r, o.MaxScanBytes)
	if err != nil {
		return nil, fmt.Errorf("transport server header: %w", err)
	}
	var dec cipher.Stream = ctr(peerKey)
	if o.plain {
		enc = nil
		dec = nil
	}
	return &Conn{Conn: raw, reader: r, readCipher: dec, writeCipher: enc}, nil
}
