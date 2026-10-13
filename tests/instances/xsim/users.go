//go:build linux

package main

// xsim users: the devices, live. Each device runs the model (model.go) in
// real time with an Xray-style mux client: sessions go onto mux connections
// (VLESS over TCP with the HTTP header) by Xray's own picking rule, idle
// connections are left to the server unless the device closes them itself,
// the device's download rate is capped by reading no faster than its
// bandwidth, and a device that drops off the network goes silent (with
// -nft, its packets are dropped so the server hears nothing more).

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type usersCfg struct {
	m        *Model
	inbounds []string // host:port
	uuid     [16]byte
	dialect  byte
	http     bool
	srcByNet [][]string // per net class
	sites    [][]string // per site class
	dead     []string
	nft      bool
}

var (
	cfg      *usersCfg
	t0       time.Time
	curPhase atomic.Int32
	measure  atomic.Bool

	// gauges
	gDevices, gMux, gTCP, gUDP, gStalls atomic.Int64
	// counters
	cMuxDials, cMuxDialFail, cMuxHsFail, cMuxServerIdle, cMuxServerBusy, cMuxClientIdle atomic.Int64
	cSessions, cSessOK, cSessFail, cSessTimeout, cSessDead, cSessSiteClosed             atomic.Int64
	cDown, cUp, cUDPOut, cUDPIn, cVanish, cDevArrive, cDevLeave                         atomic.Int64
	cExchanges, cStallsOpened                                                           atomic.Int64
	lastErr                                                                             atomic.Value

	hConnect, hTTFB, hExchange [16]*hist // per phase
	mediaWant, mediaGot        [16]atomic.Int64
)

func usersMain(args []string) {
	fs := flag.NewFlagSet("users", flag.ExitOnError)
	modelPath := fs.String("model", "model.json", "model")
	inbounds := fs.String("inbounds", "", "host:port,... of the inbounds (devices spread over them)")
	uuidStr := fs.String("uuid", "", "the client id")
	dialect := fs.Int("dialect", 0, "VLESS request version byte (the inbound's dialect)")
	useHTTP := fs.Bool("http", true, "the TCP HTTP header")
	srcNet := fs.String("src", "", "source addresses per net class: name=a-b;name=a-b (all classes)")
	siteAddrs := fs.String("sites", "", "site addresses per site class: name=a-b;name=a-b")
	dead := fs.String("dead", "", "addresses that never answer")
	phasesStr := fs.String("phases", "1:300", "scale:seconds,...")
	ramp := fs.Float64("ramp", 120, "seconds over which a phase's new devices come online")
	warm := fs.Float64("warm", 120, "seconds at the start of a phase not measured")
	out := fs.String("out", "", "write the result JSON here")
	useNft := fs.Bool("nft", false, "drop a vanished device's packets with nft (set inet xsim vanish)")
	seed := fs.Uint64("seed", 1, "random seed")
	fs.Parse(args)

	m, err := loadModel(*modelPath)
	if err != nil {
		die(err)
	}
	cfg = &usersCfg{m: m, dialect: byte(*dialect), http: *useHTTP, nft: *useNft}
	for _, s := range strings.Split(*inbounds, ",") {
		if s != "" {
			cfg.inbounds = append(cfg.inbounds, s)
		}
	}
	b, err := hex.DecodeString(strings.ReplaceAll(*uuidStr, "-", ""))
	if err != nil || len(b) != 16 || len(cfg.inbounds) == 0 {
		die(errors.New("-uuid and -inbounds are needed"))
	}
	copy(cfg.uuid[:], b)
	byName := func(spec string, names []string) [][]string {
		out := make([][]string, len(names))
		for _, part := range strings.Split(spec, ";") {
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			for i, n := range names {
				if n == k {
					out[i] = parseIPs(v)
				}
			}
		}
		for i, n := range names {
			if len(out[i]) == 0 {
				die(fmt.Errorf("no addresses for %q", n))
			}
		}
		return out
	}
	var netNames, siteNames []string
	for _, n := range m.Net {
		netNames = append(netNames, n.Name)
	}
	for _, s := range m.Sites {
		siteNames = append(siteNames, s.Name)
	}
	cfg.srcByNet = byName(*srcNet, netNames)
	cfg.sites = byName(*siteAddrs, siteNames)
	cfg.dead = parseIPs(*dead)
	if len(cfg.dead) == 0 {
		cfg.dead = cfg.sites[0]
	}
	type phase struct {
		scale float64
		dur   time.Duration
	}
	var phases []phase
	for _, p := range strings.Split(*phasesStr, ",") {
		a, b, _ := strings.Cut(p, ":")
		sc, _ := strconv.ParseFloat(a, 64)
		sec, _ := strconv.ParseFloat(b, 64)
		phases = append(phases, phase{sc, time.Duration(sec * float64(time.Second))})
	}
	if len(phases) > len(hConnect) {
		die(errors.New("too many phases"))
	}
	for i := range hConnect {
		hConnect[i], hTTFB[i], hExchange[i] = &hist{}, &hist{}, &hist{}
	}
	if cfg.nft {
		startNft()
	}

	t0 = time.Now()
	go progress()
	rng := mrand.New(mrand.NewPCG(*seed, 11))
	var rngMu sync.Mutex
	newRand := func() *mrand.Rand {
		rngMu.Lock()
		defer rngMu.Unlock()
		return mrand.New(mrand.NewPCG(rng.Uint64(), rng.Uint64()))
	}
	// devices arrive as a Poisson process sized for the phase's scale; new
	// devices for a bigger scale come online over the ramp
	var target atomic.Value
	target.Store(0.0)
	go func() {
		for {
			tg := target.Load().(float64)
			if tg <= 0 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			rate := tg / m.meanOnline
			time.Sleep(time.Duration(rng.ExpFloat64() / rate * float64(time.Second)))
			go runDevice(newRand(), false)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	type phaseOut struct {
		Scale        float64            `json:"scale"`
		StartUnix    float64            `json:"startUnix"`
		MeasureFrom  float64            `json:"measureFromUnix"`
		EndUnix      float64            `json:"endUnix"`
		Devices      float64            `json:"devices"`
		Mux          float64            `json:"mux"`
		TCP          float64            `json:"tcpSessions"`
		UDP          float64            `json:"udpSessions"`
		Rates        map[string]float64 `json:"perSec"`
		Totals       map[string]int64   `json:"totals"`
		ConnectMs    map[string]float64 `json:"tcpConnectMs"`
		TTFBMs       map[string]float64 `json:"ttfbMs"`
		ExchangeMs   map[string]float64 `json:"exchangeMs"`
		MediaRateMet float64            `json:"mediaRateMet"`
		LastError    string             `json:"lastError,omitempty"`
	}
	var outs []phaseOut
	prev := 0.0
	stopped := false
	for i, p := range phases {
		curPhase.Store(int32(i))
		measure.Store(false)
		start := time.Now()
		target.Store(m.Devices.Online * p.scale)
		if add := int(m.Devices.Online * (p.scale - prev)); add > 0 {
			go func(n int) {
				for k := 0; k < n; k++ {
					time.Sleep(time.Duration(*ramp / float64(n) * float64(time.Second)))
					go runDevice(newRand(), true)
				}
			}(add)
		}
		prev = p.scale
		w := time.Duration(*warm * float64(time.Second))
		if w > p.dur/2 {
			w = p.dur / 2
		}
		select {
		case <-time.After(w):
		case <-sig:
			stopped = true
		}
		if stopped {
			break
		}
		snap := snapshot()
		from := time.Now()
		measure.Store(true)
		// sample the gauges every second
		var n, sd, sm, st, su float64
		end := start.Add(p.dur)
		for time.Now().Before(end) && !stopped {
			select {
			case <-time.After(time.Second):
			case <-sig:
				stopped = true
			}
			n++
			sd += float64(gDevices.Load())
			sm += float64(gMux.Load())
			st += float64(gTCP.Load())
			su += float64(gUDP.Load())
		}
		measure.Store(false)
		secs := time.Since(from).Seconds()
		after := snapshot()
		o := phaseOut{Scale: p.scale, StartUnix: unix(start), MeasureFrom: unix(from), EndUnix: unix(time.Now()),
			Devices: sd / n, Mux: sm / n, TCP: st / n, UDP: su / n, Rates: map[string]float64{}, Totals: map[string]int64{}}
		for k, v := range after {
			o.Totals[k] = v - snap[k]
			o.Rates[k] = float64(v-snap[k]) / secs
		}
		o.ConnectMs = pcts(hConnect[i])
		o.TTFBMs = pcts(hTTFB[i])
		o.ExchangeMs = pcts(hExchange[i])
		// how close big downloads came to the device's own bandwidth (1 = as fast as it allows)
		if g := mediaGot[i].Load(); g > 0 {
			o.MediaRateMet = float64(mediaWant[i].Load()) / float64(g)
		}
		if e, ok := lastErr.Load().(string); ok {
			o.LastError = e
		}
		outs = append(outs, o)
		b, _ := json.Marshal(o)
		fmt.Fprintf(os.Stderr, "phase %s\n", b)
		if stopped {
			break
		}
	}
	res := map[string]any{"phases": outs, "model": *modelPath, "inbounds": cfg.inbounds}
	b, _ = json.MarshalIndent(res, "", " ")
	if *out != "" {
		os.WriteFile(*out, b, 0o644)
	}
	fmt.Println(string(b))
	os.Exit(0)
}

func unix(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func setErr(where string, err error) {
	if err != nil {
		lastErr.Store(where + ": " + err.Error())
	}
}

func snapshot() map[string]int64 {
	return map[string]int64{
		"muxDials": cMuxDials.Load(), "muxDialFail": cMuxDialFail.Load(), "muxHandshakeFail": cMuxHsFail.Load(),
		"muxServerIdleClose": cMuxServerIdle.Load(), "muxServerClosedBusy": cMuxServerBusy.Load(), "muxClientIdleClose": cMuxClientIdle.Load(),
		"sessions": cSessions.Load(), "sessionsOK": cSessOK.Load(), "sessionsFailed": cSessFail.Load(), "sessionTimeouts": cSessTimeout.Load(),
		"sessionsDeadDest": cSessDead.Load(), "sessionsClosedBySite": cSessSiteClosed.Load(), "exchanges": cExchanges.Load(),
		"downBytes": cDown.Load(), "upBytes": cUp.Load(), "udpOut": cUDPOut.Load(), "udpIn": cUDPIn.Load(),
		"devicesArrived": cDevArrive.Load(), "devicesLeft": cDevLeave.Load(), "devicesVanished": cVanish.Load(), "stalls": cStallsOpened.Load(),
	}
}

func pcts(h *hist) map[string]float64 {
	p, n, max := h.percentiles(0.5, 0.9, 0.99, 0.999)
	return map[string]float64{"p50": p[0], "p90": p[1], "p99": p[2], "p999": p[3], "max": max, "n": float64(n)}
}

func progress() {
	var lastDown, lastSess, lastDial int64
	for {
		time.Sleep(10 * time.Second)
		d, s, dl := cDown.Load(), cSessions.Load(), cMuxDials.Load()
		e, _ := lastErr.Load().(string)
		fmt.Fprintf(os.Stderr, "%s phase=%d devices=%d mux=%d tcp=%d udp=%d stalls=%d down=%.1fMB/s sess/s=%d muxdials/s=%d dialFail=%d hsFail=%d busyClosed=%d sessFail=%d timeouts=%d last=%q\n",
			time.Now().Format("15:04:05"), curPhase.Load(), gDevices.Load(), gMux.Load(), gTCP.Load(), gUDP.Load(), gStalls.Load(),
			float64(d-lastDown)/10e6, (s-lastSess)/10, (dl-lastDial)/10, cMuxDialFail.Load(), cMuxHsFail.Load(), cMuxServerBusy.Load(),
			cSessFail.Load(), cSessTimeout.Load(), e)
		lastDown, lastSess, lastDial = d, s, dl
	}
}

// ------------------------------------------------------------ devices

type limiter struct {
	mu   sync.Mutex
	rate float64 // bytes per second
	next time.Time
}

// wait spends n bytes of the budget, sleeping when ahead of it (bursts of
// up to 100 ms of the rate pass).
func (l *limiter) wait(n int) {
	if l == nil || l.rate <= 0 || n <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now.Add(-100 * time.Millisecond)) {
		l.next = now.Add(-100 * time.Millisecond)
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	d := time.Until(l.next)
	l.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

type device struct {
	p        devProfile
	r        *mrand.Rand
	rmu      sync.Mutex
	src      string
	inbound  string
	down, up *limiter
	mu       sync.Mutex
	tcp, udp []*worker
	all      map[*worker]bool
	quit     chan struct{} // closed when the device leaves
	vanished atomic.Bool
}

func (d *device) rand() *mrand.Rand { return d.r }

// rf draws from the device's random source (sessions run concurrently).
func (d *device) rf(f func(r *mrand.Rand) float64) float64 {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	return f(d.r)
}

func (d *device) sleep(sec float64) bool {
	if sec <= 0 {
		select {
		case <-d.quit:
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(time.Duration(sec * float64(time.Second)))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-d.quit:
		return false
	}
}

func runDevice(r *mrand.Rand, residual bool) {
	m := cfg.m
	d := &device{r: r, quit: make(chan struct{}), all: map[*worker]bool{}}
	d.p = newProfile(m, r)
	life := d.p.online
	if residual {
		d.p.online = residualOnline(m, r)
		life = d.p.online * r.Float64()
	}
	srcs := cfg.srcByNet[d.p.net]
	d.src = srcs[r.IntN(len(srcs))]
	d.inbound = cfg.inbounds[r.IntN(len(cfg.inbounds))]
	d.down = &limiter{rate: d.p.downBps}
	d.up = &limiter{rate: d.p.upBps}
	gDevices.Add(1)
	cDevArrive.Add(1)
	defer gDevices.Add(-1)

	for c, sc := range m.Sessions {
		for i := 0; i < sc.AtConnect; i++ {
			go d.connectLoop(c)
		}
		if sc.Every.Type != "" || sc.Every.V > 0 {
			go d.everyLoop(c)
		}
	}
	if m.Devices.StallRate > 0 {
		go d.stallLoop()
	}
	arr := newArrivals(m, mrand.New(mrand.NewPCG(r.Uint64(), r.Uint64())), life)
	start := time.Now()
	for {
		t, c, ok := arr.next()
		if !ok {
			break
		}
		if !d.sleep(time.Until(start.Add(time.Duration(t * float64(time.Second)))).Seconds()) {
			break
		}
		n := burst(m, d.r, c)
		for i := 0; i < n; i++ {
			delay := 0.0
			if i > 0 {
				delay = d.rf(func(r *mrand.Rand) float64 { return r.Float64() * 0.3 })
			}
			go d.session(c, delay)
		}
	}
	d.sleep(time.Until(start.Add(time.Duration(life * float64(time.Second)))).Seconds())
	d.leave()
}

func (d *device) connectLoop(c int) {
	if !d.sleep(d.rf(func(r *mrand.Rand) float64 { return r.Float64() * 3 })) {
		return
	}
	for {
		d.session(c, 0)
		if !d.sleep(d.rf(func(r *mrand.Rand) float64 { return 1 + r.Float64()*4 })) {
			return
		}
	}
}

func (d *device) everyLoop(c int) {
	every := func() float64 { return d.rf(cfg.m.Sessions[c].Every.Sample) }
	if !d.sleep(d.rf(func(r *mrand.Rand) float64 { return r.Float64() }) * every()) {
		return
	}
	for {
		go d.session(c, 0)
		if !d.sleep(every()) {
			return
		}
	}
}

// stallLoop opens connections that never send their request, as when the
// first packet is lost on the way: the client gives up, or the server's
// handshake timeout closes them.
func (d *device) stallLoop() {
	m := cfg.m
	for {
		if !d.sleep(d.rf(func(r *mrand.Rand) float64 { return r.ExpFloat64() / m.Devices.StallRate })) {
			return
		}
		go func() {
			c, err := d.dial()
			if err != nil {
				return
			}
			defer c.Close()
			cStallsOpened.Add(1)
			gStalls.Add(1)
			defer gStalls.Add(-1)
			wait := d.rf(m.Devices.StallSec.Sample)
			c.SetReadDeadline(time.Now().Add(time.Duration(wait * float64(time.Second))))
			var b [1]byte
			c.Read(b[:])
		}()
	}
}

func (d *device) dial() (net.Conn, error) {
	dl := net.Dialer{Timeout: 20 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(d.src)}}
	return dl.Dial("tcp", d.inbound)
}

func (d *device) leave() {
	cDevLeave.Add(1)
	if d.p.vanish {
		cVanish.Add(1)
		d.vanished.Store(true)
	}
	close(d.quit)
	d.mu.Lock()
	ws := make([]*worker, 0, len(d.all))
	for w := range d.all {
		ws = append(ws, w)
	}
	d.mu.Unlock()
	for _, w := range ws {
		if d.p.vanish {
			w.vanish()
		} else {
			w.close("device left")
		}
	}
}

// ------------------------------------------------------------ mux connections

type msess struct {
	id     uint16
	w      *worker
	got    atomic.Int64
	notify chan struct{}
	ended  atomic.Bool
	endWhy atomic.Value
	udp    bool
}

func (s *msess) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

type worker struct {
	d        *device
	xudp     bool
	conn     net.Conn
	wmu      sync.Mutex
	pending  []byte // the request header, sent with the first frame
	mu       sync.Mutex
	sessions map[uint16]*msess
	nextID   uint16
	size     int
	count    int
	closed   bool
	ready    chan struct{}
	readyErr error
	born     time.Time
	cSize    int
	cCnt     int
}

func (d *device) newWorker(xudp bool) (*worker, error) {
	cMuxDials.Add(1)
	t := time.Now()
	c, err := d.dial()
	if err != nil {
		cMuxDialFail.Add(1)
		setErr("dial", err)
		return nil, err
	}
	if measure.Load() {
		// the TCP handshake with the inbound: the network's round trip plus
		// however long the server's accept queue makes it wait
		hConnect[curPhase.Load()].add(0, time.Since(t))
	}
	w := &worker{d: d, xudp: xudp, conn: c, sessions: map[uint16]*msess{}, ready: make(chan struct{}), born: t}
	w.pending = vlessRequest(nil, cfg.http, cfg.dialect, cfg.uuid, cmdMux, 0, "")
	d.mu.Lock()
	d.all[w] = true
	d.mu.Unlock()
	gMux.Add(1)
	go w.read(t)
	if d.p.closeIdle {
		go w.idleLoop()
	}
	return w, nil
}

// pick is Xray's mux client picking, on the device's TCP or XUDP pool.
func (d *device) pick(xudp bool) (*worker, *msess, error) {
	m := cfg.m
	conc := m.Mux.Concurrency
	pool := &d.tcp
	if xudp {
		conc = m.Mux.XudpConcurrency
		pool = &d.udp
	}
	d.mu.Lock()
	w := pickWorker(pool, func(w *worker) bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.closed || w.size >= conc || w.count >= m.Mux.MaxConnection
	})
	if w != nil {
		s := w.add()
		d.mu.Unlock()
		if s != nil {
			return w, s, nil
		}
		d.mu.Lock()
	}
	live := (*pool)[:0]
	for _, x := range *pool {
		x.mu.Lock()
		if !x.closed {
			live = append(live, x)
		}
		x.mu.Unlock()
	}
	*pool = live
	d.mu.Unlock()
	nw, err := d.newWorker(xudp)
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	*pool = append(*pool, nw)
	s := nw.add()
	d.mu.Unlock()
	if s == nil {
		return nil, nil, errors.New("new mux connection closed")
	}
	return nw, s, nil
}

func (w *worker) add() *msess {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.nextID++
	s := &msess{id: w.nextID, w: w, notify: make(chan struct{}, 1), udp: w.xudp}
	w.sessions[s.id] = s
	w.size++
	w.count++
	return s
}

func (w *worker) remove(s *msess) {
	w.mu.Lock()
	if _, ok := w.sessions[s.id]; ok {
		delete(w.sessions, s.id)
		w.size--
	}
	w.mu.Unlock()
}

// write sends one frame (the request header first, on the first one).
func (w *worker) write(frame []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.pending != nil {
		frame = append(w.pending, frame...)
		w.pending = nil
	}
	w.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	_, err := w.conn.Write(frame)
	return err
}

type throttled struct {
	w *worker
}

func (t throttled) Read(p []byte) (int, error) {
	if t.w.d.vanished.Load() {
		<-t.w.d.quit
		return 0, io.EOF
	}
	n, err := t.w.conn.Read(p)
	t.w.d.down.wait(n)
	return n, err
}

func (w *worker) read(born time.Time) {
	br := bufio.NewReaderSize(throttled{w}, 32<<10)
	// The response header comes with the first data back, which can take
	// as long as the first session's site does; a client does not time it
	// out.
	err := readVlessResponse(br, cfg.http)
	if err != nil {
		if !w.d.vanished.Load() {
			cMuxHsFail.Add(1)
			setErr("mux handshake", err)
		}
		w.readyErr = err
		close(w.ready)
		w.close("handshake")
		return
	}
	close(w.ready)
	var meta [512]byte
	var l [2]byte
	for {
		if _, err := io.ReadFull(br, l[:]); err != nil {
			w.closedByServer(err)
			return
		}
		ml := int(l[0])<<8 | int(l[1])
		if ml < 4 || ml > len(meta) {
			w.closedByServer(fmt.Errorf("bad mux metadata length %d", ml))
			return
		}
		if _, err := io.ReadFull(br, meta[:ml]); err != nil {
			w.closedByServer(err)
			return
		}
		id := uint16(meta[0])<<8 | uint16(meta[1])
		status, opt := meta[2], meta[3]
		n := 0
		if opt&1 != 0 {
			if _, err := io.ReadFull(br, l[:]); err != nil {
				w.closedByServer(err)
				return
			}
			n = int(l[0])<<8 | int(l[1])
			if _, err := br.Discard(n); err != nil {
				w.closedByServer(err)
				return
			}
			cDown.Add(int64(n))
		}
		w.mu.Lock()
		s := w.sessions[id]
		w.mu.Unlock()
		if s == nil {
			continue
		}
		if n > 0 {
			s.got.Add(int64(n))
			if s.udp {
				cUDPIn.Add(1)
			}
			s.signal()
		}
		if status == 3 { // End: the site (or the core) closed it
			s.endWhy.Store("site")
			s.ended.Store(true)
			s.signal()
		}
	}
}

func (w *worker) closedByServer(err error) {
	w.mu.Lock()
	busy := w.size > 0
	already := w.closed
	w.mu.Unlock()
	if !already && !w.d.vanished.Load() {
		if busy {
			cMuxServerBusy.Add(1)
			setErr("mux closed with sessions", err)
		} else {
			cMuxServerIdle.Add(1)
		}
	}
	w.close("server")
}

func (w *worker) close(why string) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	ss := make([]*msess, 0, len(w.sessions))
	for _, s := range w.sessions {
		ss = append(ss, s)
	}
	w.mu.Unlock()
	w.conn.Close()
	gMux.Add(-1)
	for _, s := range ss {
		s.endWhy.Store("mux " + why)
		s.ended.Store(true)
		s.signal()
	}
	w.d.mu.Lock()
	delete(w.d.all, w)
	w.d.mu.Unlock()
}

// vanish: the device is gone from the network. With -nft its packets are
// dropped from now on, so closing the socket tells the server nothing.
func (w *worker) vanish() {
	if cfg.nft {
		if la, ok := w.conn.LocalAddr().(*net.TCPAddr); ok {
			nftDrop(la.IP.String(), la.Port)
		}
		time.AfterFunc(2*time.Second, func() { w.closeSilently() })
		return
	}
	// without nft: stop reading and writing, keep the socket until the
	// server gives up on it
	go func() {
		time.Sleep(20 * time.Minute)
		w.closeSilently()
	}()
}

func (w *worker) closeSilently() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	if tc, ok := w.conn.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	w.conn.Close()
	gMux.Add(-1)
}

// idleLoop is Xray's client-side check, for devices whose client closes
// idle mux connections: every 16 s, close if there was no session at the
// last check and none came or went since.
func (w *worker) idleLoop() {
	t := time.NewTicker(16 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-w.d.quit:
			return
		}
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		closeIt := idleCheck(w.size, &w.cSize, &w.cCnt, w.count)
		w.mu.Unlock()
		if closeIt {
			cMuxClientIdle.Add(1)
			w.close("client idle")
			return
		}
	}
}

// ------------------------------------------------------------ sessions

func frameNew(id uint16, udp bool, port int, addr string, globalID []byte, data []byte) []byte {
	b := make([]byte, 0, 64+len(data))
	b = append(b, 0, 0, byte(id>>8), byte(id), 1)
	if len(data) > 0 {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	if udp {
		b = append(b, 2)
	} else {
		b = append(b, 1)
	}
	b = append(b, byte(port>>8), byte(port))
	b = appendAddr(b, addr)
	if udp {
		b = append(b, globalID...)
	}
	l := len(b) - 2
	b[0], b[1] = byte(l>>8), byte(l)
	if len(data) > 0 {
		b = append(b, byte(len(data)>>8), byte(len(data)))
		b = append(b, data...)
	}
	return b
}

func frameKeep(id uint16, udp bool, port int, addr string, data []byte) []byte {
	b := make([]byte, 0, 32+len(data))
	b = append(b, 0, 0, byte(id>>8), byte(id), 2, 1)
	if udp {
		b = append(b, 2, byte(port>>8), byte(port))
		b = appendAddr(b, addr)
	}
	l := len(b) - 2
	b[0], b[1] = byte(l>>8), byte(l)
	b = append(b, byte(len(data)>>8), byte(len(data)))
	return append(b, data...)
}

func frameEnd(id uint16) []byte { return []byte{0, 4, byte(id >> 8), byte(id), 3, 0} }

var pad = make([]byte, 64<<10)

// session runs one session of class c, after delay seconds.
func (d *device) session(c int, delay float64) {
	if !d.sleep(delay) {
		return
	}
	m := cfg.m
	d.rmu.Lock()
	sc := makeScript(m, d.r, c)
	var addr string
	if sc.site < 0 {
		addr = cfg.dead[d.r.IntN(len(cfg.dead))]
	} else {
		as := cfg.sites[sc.site]
		addr = as[d.r.IntN(len(as))]
	}
	gid := make([]byte, 8)
	for i := range gid {
		gid[i] = byte(d.r.Uint32())
	}
	d.rmu.Unlock()

	var w *worker
	var s *msess
	var err error
	if m.Sessions[c].Fresh {
		// a mux connection of its own, never reused
		if w, err = d.newWorker(sc.udp); err == nil {
			if s = w.add(); s == nil {
				err = errors.New("closed")
			}
		}
	} else {
		w, s, err = d.pick(sc.udp)
	}
	if err != nil {
		cSessFail.Add(1)
		return
	}
	cSessions.Add(1)
	switch {
	case sc.udp:
		gUDP.Add(1)
		defer gUDP.Add(-1)
	case sc.site >= 0:
		gTCP.Add(1)
		defer gTCP.Add(-1)
	}
	defer w.remove(s)
	var why string
	if sc.udp {
		why = d.runUDP(w, s, sc, addr, gid)
	} else {
		why = d.runTCP(w, s, sc, addr)
	}
	switch why {
	case "ok":
		cSessOK.Add(1)
	case "site":
		cSessOK.Add(1)
		cSessSiteClosed.Add(1)
	case "dead":
		cSessDead.Add(1)
	case "left":
	case "timeout":
		cSessTimeout.Add(1)
		cSessFail.Add(1)
	default:
		cSessFail.Add(1)
		setErr("session", errors.New(why))
	}
	if why != "left" && !s.ended.Load() {
		w.write(frameEnd(s.id))
	}
}

// send writes data for the session as mux frames of up to 8 KB (as Xray's
// mux writer splits them), the first one opening the session.
func (d *device) send(w *worker, s *msess, first *bool, sc script, addr string, gid []byte, data []byte) error {
	for len(data) > 0 || *first {
		n := len(data)
		if n > 8000 {
			n = 8000
		}
		d.up.wait(n)
		var f []byte
		if *first {
			f = frameNew(s.id, sc.udp, sc.port, addr, gid, data[:n])
			*first = false
		} else {
			f = frameKeep(s.id, sc.udp, sc.port, addr, data[:n])
		}
		if err := w.write(f); err != nil {
			return err
		}
		cUp.Add(int64(n))
		data = data[n:]
	}
	return nil
}

// await waits until the session has received want bytes in all, it ends,
// the device leaves or the time runs out. ttfb is set at the first new byte.
func (d *device) await(s *msess, want int64, timeout time.Duration, from time.Time, ttfb *time.Duration) string {
	start := s.got.Load()
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		g := s.got.Load()
		if g > start && *ttfb == 0 {
			*ttfb = time.Since(from)
		}
		if g >= want {
			return "ok"
		}
		if s.ended.Load() {
			why, _ := s.endWhy.Load().(string)
			if why == "" {
				why = "ended"
			}
			return why
		}
		select {
		case <-s.notify:
		case <-t.C:
			return "timeout"
		case <-d.quit:
			return "left"
		}
	}
}

func (d *device) runTCP(w *worker, s *msess, sc script, addr string) string {
	first := true
	if sc.site < 0 {
		// a destination that never answers: the client gives up after a while
		if err := d.send(w, s, &first, sc, addr, nil, pad[:517]); err != nil {
			return "write: " + err.Error()
		}
		var ttfb time.Duration
		switch why := d.await(s, 1<<62, time.Duration(sc.deadWait*float64(time.Second)), time.Now(), &ttfb); why {
		case "left":
			return why
		}
		return "dead"
	}
	ph := int(curPhase.Load())
	for i, st := range sc.steps {
		if i > 0 && !d.sleep(st.gap) {
			return "left"
		}
		req := siteCmd{Op: opRespond, ReqLen: uint32(st.req), RespLen: uint32(st.resp), DelayMs: uint16(min(st.think, 65535))}.append(nil)
		req = append(req, pad[:min(st.req, len(pad))]...)
		for extra := st.req - len(pad); extra > 0; extra -= len(pad) {
			req = append(req, pad[:min(extra, len(pad))]...)
		}
		from := time.Now()
		want := s.got.Load() + int64(st.resp)
		if err := d.send(w, s, &first, sc, addr, nil, req); err != nil {
			return "write: " + err.Error()
		}
		cExchanges.Add(1)
		var ttfb time.Duration
		// generous: the device's other sessions share its bandwidth and its
		// mux connection, and what the server already queued on that
		// connection (up to its 4 MB send buffer) drains at the device's rate
		expect := float64(st.resp) / d.p.downBps
		why := d.await(s, want, time.Duration((60+10*expect+2*4e6/d.p.downBps)*float64(time.Second)), from, &ttfb)
		if why != "ok" {
			return why
		}
		took := time.Since(from)
		if measure.Load() {
			hTTFB[ph].add(0, ttfb)
			hExchange[ph].add(0, took)
			if st.resp >= 100000 {
				mediaWant[ph].Add(int64(expect * 1000))
				mediaGot[ph].Add(took.Milliseconds())
			}
		}
	}
	// held: pushes from the site, heartbeats from the client, and the
	// site's keep-alive timeout, until the client lets go
	if sc.pushEvery > 0 {
		cmd := siteCmd{Op: opPush, RespLen: uint32(sc.pushBytes), DelayMs: uint16(min(sc.pushEvery*100, 65535))}.append(nil)
		if err := d.send(w, s, &first, sc, addr, nil, cmd); err != nil {
			return "write: " + err.Error()
		}
	}
	hold := sc.hold
	if sc.siteIdle > 0 && sc.heartbeat == 0 && sc.siteIdle < hold {
		cmd := siteCmd{Op: opClose, DelayMs: uint16(min(sc.siteIdle*10, 65535))}.append(nil)
		if err := d.send(w, s, &first, sc, addr, nil, cmd); err != nil {
			return "write: " + err.Error()
		}
	}
	end := time.Now().Add(time.Duration(hold * float64(time.Second)))
	for {
		left := time.Until(end)
		if left <= 0 {
			return "ok"
		}
		wait := left
		if sc.heartbeat > 0 && time.Duration(sc.heartbeat*float64(time.Second)) < wait {
			wait = time.Duration(sc.heartbeat * float64(time.Second))
		}
		var ttfb time.Duration
		switch why := d.await(s, 1<<62, wait, time.Now(), &ttfb); why {
		case "timeout":
			if sc.heartbeat > 0 && time.Until(end) > 0 {
				hb := siteCmd{Op: opRespond, ReqLen: 48, RespLen: 64}.append(nil)
				hb = append(hb, pad[:48]...)
				if err := d.send(w, s, &first, sc, addr, nil, hb); err != nil {
					return "write: " + err.Error()
				}
			}
		case "site":
			return "site"
		default:
			return why
		}
	}
}

func (d *device) runUDP(w *worker, s *msess, sc script, addr string, gid []byte) string {
	first := true
	if sc.site < 0 {
		return "dead"
	}
	size := max(sc.pkt, udpHeaderLen)
	end := time.Now().Add(time.Duration(sc.life * float64(time.Second)))
	for time.Now().Before(end) {
		pkt := udpCmd(make([]byte, 0, size), sc.replies, sc.pkt, 0)
		pkt = append(pkt, pad[:size-udpHeaderLen]...)
		if err := d.send(w, s, &first, sc, addr, gid, pkt); err != nil {
			return "write: " + err.Error()
		}
		cUDPOut.Add(1)
		gap := d.rf(func(r *mrand.Rand) float64 { return r.ExpFloat64() / math.Max(sc.pps, 0.01) })
		if rem := time.Until(end).Seconds(); gap > rem {
			gap = rem
		}
		if !d.sleep(gap) {
			return "left"
		}
		if s.ended.Load() {
			return "ok"
		}
	}
	return "ok"
}

// ------------------------------------------------------------ nft

var nftCh chan string

// startNft batches "drop this socket" elements into the inbound-side
// netns's set: table inet xsim, set vanish (ipv4_addr . inet_service).
func startNft() {
	if _, err := exec.LookPath("nft"); err != nil {
		die(errors.New("-nft needs the nft command"))
	}
	nftCh = make(chan string, 1<<16)
	go func() {
		var batch []string
		flush := func() {
			if len(batch) == 0 {
				return
			}
			cmd := exec.Command("nft", "add element inet xsim vanish { "+strings.Join(batch, ", ")+" }")
			if out, err := cmd.CombinedOutput(); err != nil {
				setErr("nft", fmt.Errorf("%v: %s", err, out))
			}
			batch = batch[:0]
		}
		t := time.NewTicker(500 * time.Millisecond)
		for {
			select {
			case e := <-nftCh:
				batch = append(batch, e)
				if len(batch) >= 500 {
					flush()
				}
			case <-t.C:
				flush()
			}
		}
	}()
}

func nftDrop(ip string, port int) {
	select {
	case nftCh <- ip + " . " + strconv.Itoa(port):
	default:
	}
}

var _ = rand.Read
