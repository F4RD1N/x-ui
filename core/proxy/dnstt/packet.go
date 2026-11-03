package dnstt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport/internet"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

// The KCP peer is the tunnel session, independently of which explicitly
// configured recursive resolver carries a particular DNS transaction.
type tunnelAddr string

func (a tunnelAddr) Network() string { return "dnstt" }
func (a tunnelAddr) String() string  { return string(a) }

var carrierRemoteAddr net.Addr = tunnelAddr("server")
var tunnelBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// packetMTU uses the worst-case number of labels so randomized splitting can
// never grow a query beyond maxQnameLength. Padding and the eight-byte stock
// ClientID are included. Only the last label may be shorter than labelMin.
func packetMTU(c *Config) (int, error) {
	domain, err := dns.ParseName(c.Domain)
	if err != nil {
		return 0, err
	}
	suffix := 1
	for _, label := range domain {
		suffix += 1 + len(label)
	}
	labelMin := int(c.LabelMin)
	if labelMin == 0 {
		labelMin = 63
	}
	limit := int(c.MaxQnameLength)
	if limit == 0 {
		limit = 255
	}
	mtu := 0
	for n := 1; n < 224; n++ {
		encoded := tunnelBase32.EncodedLen(8 + 1 + 3 + 1 + n)
		if suffix+encoded+(encoded+labelMin-1)/labelMin > limit {
			break
		}
		mtu = n
	}
	if mtu < 80 {
		return 0, errors.New("dnstt: tunnel domain and label/QNAME settings leave less than 80 bytes for KCP")
	}
	return mtu, nil
}

type packetDeadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func newPacketDeadline() packetDeadline { return packetDeadline{changed: make(chan struct{})} }
func (d *packetDeadline) set(at time.Time) {
	d.mu.Lock()
	d.at = at
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}
func (d *packetDeadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.at.IsZero() && !time.Now().Before(d.at)
}
func (d *packetDeadline) wait() (chan struct{}, <-chan time.Time, func()) {
	d.mu.Lock()
	at, changed := d.at, d.changed
	d.mu.Unlock()
	if at.IsZero() {
		return changed, nil, func() {}
	}
	timer := time.NewTimer(time.Until(at))
	return changed, timer.C, func() { timer.Stop() }
}

type dnsPacketConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	cfg       *Config
	domain    dns.Name
	clientID  [8]byte
	mtu       int
	outgoing  chan []byte
	incoming  chan []byte
	poll      chan struct{}
	slots     chan struct{}
	resolvers *resolverSet
	rd, wd    packetDeadline
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newPacketConn(ctx context.Context, c *Config, dialer internet.Dialer) (net.PacketConn, error) {
	if ctx == nil || dialer == nil {
		return nil, errors.New("dnstt: context and Xray dialer required")
	}
	mtu, err := packetMTU(c)
	if err != nil {
		return nil, err
	}
	domain, err := dns.ParseName(c.Domain)
	if err != nil {
		return nil, err
	}
	base, cancel := context.WithCancel(ctx)
	pc := &dnsPacketConn{ctx: base, cancel: cancel, cfg: c, domain: domain, mtu: mtu, outgoing: make(chan []byte, 256), incoming: make(chan []byte, 256), poll: make(chan struct{}, 16), slots: make(chan struct{}, c.MaxConcurrentQueries), rd: newPacketDeadline(), wd: newPacketDeadline()}
	if _, err = rand.Read(pc.clientID[:]); err != nil {
		cancel()
		return nil, err
	}
	pc.resolvers, err = newResolverSet(base, c, dialer)
	if err != nil {
		cancel()
		return nil, err
	}
	pc.wg.Add(1)
	go func() {
		defer pc.wg.Done()
		defer nativebridge.RecoverWorker(func(error) { pc.cancel() })
		pc.sendLoop()
	}()
	return pc, nil
}
func (p *dnsPacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		if p.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		if p.rd.expired() {
			return 0, nil, os.ErrDeadlineExceeded
		}
		changed, expired, stop := p.rd.wait()
		select {
		case <-p.ctx.Done():
			stop()
			return 0, nil, net.ErrClosed
		case <-changed:
			stop()
			continue
		case <-expired:
			stop()
			return 0, nil, os.ErrDeadlineExceeded
		case packet := <-p.incoming:
			stop()
			if p.ctx.Err() != nil {
				return 0, nil, net.ErrClosed
			}
			if p.rd.expired() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			return copy(dst, packet), carrierRemoteAddr, nil
		}
	}
}
func (p *dnsPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	if p.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	if len(data) > p.mtu {
		return 0, errors.New("dnstt: packet exceeds configured DNS capacity")
	}
	packet := bytes.Clone(data)
	for {
		if p.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		if p.wd.expired() {
			return 0, os.ErrDeadlineExceeded
		}
		changed, expired, stop := p.wd.wait()
		select {
		case <-p.ctx.Done():
			stop()
			return 0, net.ErrClosed
		case <-changed:
			stop()
			continue
		case <-expired:
			stop()
			return 0, os.ErrDeadlineExceeded
		case p.outgoing <- packet:
			stop()
			return len(data), nil
		}
	}
}
func (p *dnsPacketConn) Close() error {
	p.closeOnce.Do(func() { p.cancel(); p.resolvers.Close(); p.wg.Wait() })
	return nil
}
func (p *dnsPacketConn) LocalAddr() net.Addr                { return tunnelAddr("client") }
func (p *dnsPacketConn) SetDeadline(t time.Time) error      { p.rd.set(t); p.wd.set(t); return nil }
func (p *dnsPacketConn) SetReadDeadline(t time.Time) error  { p.rd.set(t); return nil }
func (p *dnsPacketConn) SetWriteDeadline(t time.Time) error { p.wd.set(t); return nil }

func (p *dnsPacketConn) query(packet []byte) ([]byte, error) {
	padding := 3
	if len(packet) == 0 {
		padding = 8
	}
	raw := make([]byte, 8+1+padding)
	copy(raw, p.clientID[:])
	raw[8] = byte(224 + padding)
	if _, err := rand.Read(raw[9:]); err != nil {
		return nil, err
	}
	if len(packet) > 0 {
		raw = append(raw, byte(len(packet)))
		raw = append(raw, packet...)
	}
	encoded := []byte(strings.ToLower(tunnelBase32.EncodeToString(raw)))
	labels := make([][]byte, 0, 16)
	low, high := int(p.cfg.LabelMin), int(p.cfg.LabelMax)
	if low == 0 {
		low = 63
	}
	if high == 0 {
		high = 63
	}
	for len(encoded) > 0 {
		size := high
		if high > low {
			// Rejection sampling avoids modulo bias without a process-global PRNG.
			width := high - low + 1
			bound := 256 - 256%width
			var b [1]byte
			for {
				if _, err := rand.Read(b[:]); err != nil {
					return nil, err
				}
				if int(b[0]) < bound {
					size = low + int(b[0])%width
					break
				}
			}
		}
		if size > len(encoded) {
			size = len(encoded)
		}
		labels = append(labels, encoded[:size])
		encoded = encoded[size:]
	}
	labels = append(labels, p.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	length := 1
	for _, label := range name {
		length += len(label) + 1
	}
	if length > int(p.cfg.MaxQnameLength) {
		return nil, errors.New("dnstt: query exceeds configured QNAME limit")
	}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}
	message := dns.Message{ID: binary.BigEndian.Uint16(id[:]), Flags: 0x0100, Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}}, Additional: []dns.RR{{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: uint16(p.cfg.EdnsPayloadSize)}}}
	return message.WireFormat()
}

func (p *dnsPacketConn) consume(query, response []byte) {
	q, err := dns.MessageFromWireFormat(query)
	if err != nil {
		return
	}
	r, err := dns.MessageFromWireFormat(response)
	if err != nil {
		return
	}
	// DNS correlation is defence in depth; Noise authenticates the actual tunnel
	// payload. Reject truncated/error/unsolicited answers without feeding KCP.
	if r.ID != q.ID || r.Flags&0x8000 == 0 || r.Flags&0x0200 != 0 || r.Flags&0x000f != 0 || len(r.Question) != 1 || len(r.Answer) != 1 {
		return
	}
	question := r.Question[0]
	if question.Type != dns.RRTypeTXT || question.Class != dns.ClassIN || !strings.EqualFold(question.Name.String(), q.Question[0].Name.String()) {
		return
	}
	answer := r.Answer[0]
	if answer.Type != dns.RRTypeTXT || answer.Class != dns.ClassIN || !strings.EqualFold(answer.Name.String(), q.Question[0].Name.String()) {
		return
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return
	}
	reader := bytes.NewReader(payload)
	any := false
	for reader.Len() > 0 {
		var size uint16
		if binary.Read(reader, binary.BigEndian, &size) != nil || int(size) > reader.Len() {
			return
		}
		packet := make([]byte, size)
		if _, err = io.ReadFull(reader, packet); err != nil {
			return
		}
		select {
		case p.incoming <- packet:
			any = true
		case <-p.ctx.Done():
			return
		}
	}
	if any {
		select {
		case p.poll <- struct{}{}:
		default:
		}
	}
}

func (p *dnsPacketConn) sendLoop() {
	delay := 500 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var last time.Time
	for {
		var data []byte
		fromTimer := false
		select {
		case <-p.ctx.Done():
			return
		case data = <-p.outgoing:
		default:
			select {
			case <-p.ctx.Done():
				return
			case data = <-p.outgoing:
			case <-p.poll:
			case <-timer.C:
				fromTimer = true
			}
		}
		if len(data) > 0 {
			select {
			case <-p.poll:
			default:
			}
		}
		if fromTimer {
			delay *= 2
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		} else {
			delay = 500 * time.Millisecond
		}
		timer.Reset(delay)
		if pause := time.Duration(p.cfg.MinQueryIntervalMs)*time.Millisecond - time.Since(last); pause > 0 {
			pacing := time.NewTimer(pause)
			select {
			case <-p.ctx.Done():
				pacing.Stop()
				return
			case <-pacing.C:
			}
		}
		query, err := p.query(data)
		if err != nil {
			continue
		}
		select {
		case p.slots <- struct{}{}:
		case <-p.ctx.Done():
			return
		}
		last = time.Now()
		p.wg.Add(1)
		go func(query []byte) {
			defer p.wg.Done()
			defer func() { <-p.slots }()
			defer nativebridge.RecoverWorker(func(error) { p.cancel() })
			ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.cfg.QueryTimeout)*time.Second)
			defer cancel()
			response, err := p.resolvers.exchange(ctx, query)
			if err == nil {
				p.consume(query, response)
			}
		}(query)
	}
}
