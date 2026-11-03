package server

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// maxAdapterBuffer bounds the plaintext-side backlog of one key state's TLS
// adapter: received control payloads not yet read by crypto/tls. A peer that
// floods the control channel past it gets the key state closed.
const maxAdapterBuffer = 256 << 10

var errAdapterOverflow = errors.New("openvpn: control channel backlog too large")

// tlsAdapter is the net.Conn crypto/tls runs over for one key state.
//
// Write cuts the TLS bytes into chunks that fit one P_CONTROL_V1 packet and
// queues them for the control loop (which owns the key state's reliability
// layer), then wakes it; it never blocks. Read returns the in-order control
// payloads the control loop delivered, concatenated, blocking until there
// are some, the read deadline passes or the adapter is closed.
type tlsAdapter struct {
	chunk        int
	wake         func()
	laddr, raddr net.Addr

	mu       sync.Mutex
	in       []byte
	out      [][]byte
	outBytes int
	closed   bool
	err      error
	deadline time.Time
	readable chan struct{} // capacity 1: something changed for Read
}

func newTLSAdapter(chunk int, wake func(), laddr, raddr net.Addr) *tlsAdapter {
	if chunk < 1 {
		chunk = 1
	}
	if wake == nil {
		wake = func() {}
	}
	return &tlsAdapter{
		chunk:    chunk,
		wake:     wake,
		laddr:    laddr,
		raddr:    raddr,
		readable: make(chan struct{}, 1),
	}
}

func (a *tlsAdapter) signal() {
	select {
	case a.readable <- struct{}{}:
	default:
	}
}

// Read implements net.Conn.
func (a *tlsAdapter) Read(b []byte) (int, error) {
	for {
		a.mu.Lock()
		if len(a.in) > 0 {
			n := copy(b, a.in)
			a.in = a.in[n:]
			if len(a.in) == 0 {
				a.in = nil
			}
			a.mu.Unlock()
			return n, nil
		}
		if a.closed {
			err := a.err
			a.mu.Unlock()
			return 0, err
		}
		deadline := a.deadline
		a.mu.Unlock()

		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			expired = timer.C
		}
		select {
		case <-a.readable:
		case <-expired:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Write implements net.Conn.
func (a *tlsAdapter) Write(b []byte) (int, error) {
	a.mu.Lock()
	if a.closed {
		err := a.err
		a.mu.Unlock()
		return 0, err
	}
	if len(b)+a.outBytes > maxAdapterBuffer {
		a.mu.Unlock()
		a.closeWith(errAdapterOverflow)
		return 0, errAdapterOverflow
	}
	a.outBytes += len(b)
	for p := b; len(p) > 0; {
		n := min(len(p), a.chunk)
		a.out = append(a.out, bytes.Clone(p[:n]))
		p = p[n:]
	}
	a.mu.Unlock()
	a.wake()
	return len(b), nil
}

// Close implements net.Conn. It unblocks a pending Read.
func (a *tlsAdapter) Close() error {
	a.closeWith(net.ErrClosed)
	return nil
}

func (a *tlsAdapter) closeWith(err error) {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		a.err = err
		a.in = nil
		a.out = nil
		a.outBytes = 0
	}
	a.mu.Unlock()
	a.signal()
}

// deliver appends one in-order control payload for Read.
func (a *tlsAdapter) deliver(p []byte) {
	if len(p) == 0 {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	if len(a.in)+len(p) > maxAdapterBuffer {
		a.mu.Unlock()
		a.closeWith(errAdapterOverflow)
		return
	}
	a.in = append(a.in, p...)
	a.mu.Unlock()
	a.signal()
}

// takeOut returns the chunks written since the last call.
func (a *tlsAdapter) takeOut() [][]byte {
	a.mu.Lock()
	out := a.out
	a.out = nil
	a.outBytes = 0
	a.mu.Unlock()
	return out
}

// pendingOut reports how many chunks wait for the control loop.
func (a *tlsAdapter) pendingOut() int {
	a.mu.Lock()
	n := len(a.out)
	a.mu.Unlock()
	return n
}

func (a *tlsAdapter) LocalAddr() net.Addr  { return a.laddr }
func (a *tlsAdapter) RemoteAddr() net.Addr { return a.raddr }

func (a *tlsAdapter) SetDeadline(t time.Time) error {
	return a.SetReadDeadline(t)
}

func (a *tlsAdapter) SetReadDeadline(t time.Time) error {
	a.mu.Lock()
	a.deadline = t
	a.mu.Unlock()
	a.signal()
	return nil
}

// SetWriteDeadline implements net.Conn; writes never block, so it has no
// effect.
func (a *tlsAdapter) SetWriteDeadline(time.Time) error { return nil }
