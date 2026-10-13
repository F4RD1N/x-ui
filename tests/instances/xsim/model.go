//go:build linux

package main

// The simulation model: what the users' devices do. sim/model.json holds the
// numbers, fitted against a live server (sim/observe.py) with `xsim fit`.

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
)

// Dist is a distribution of a number.
//
//	{"type":"const","v":5}
//	{"type":"uniform","min":1,"max":3}
//	{"type":"exp","mean":10}
//	{"type":"lognormal","median":4000,"sigma":1.5}
//	{"type":"points","p":[[0.5,2],[0.9,30],[1,120]]}   cumulative share -> value, linear between
//
// min and max clamp every type but uniform.
type Dist struct {
	Type   string       `json:"type,omitempty"`
	V      float64      `json:"v,omitempty"`
	Min    float64      `json:"min,omitempty"`
	Max    float64      `json:"max,omitempty"`
	Mean   float64      `json:"mean,omitempty"`
	Median float64      `json:"median,omitempty"`
	Sigma  float64      `json:"sigma,omitempty"`
	P      [][2]float64 `json:"p,omitempty"`
}

func (d Dist) Sample(r *rand.Rand) float64 {
	var v float64
	switch d.Type {
	case "", "const":
		v = d.V
	case "uniform":
		return d.Min + r.Float64()*(d.Max-d.Min)
	case "exp":
		v = r.ExpFloat64() * d.Mean
	case "lognormal":
		v = d.Median * math.Exp(d.Sigma*r.NormFloat64())
	case "points":
		u := r.Float64()
		prevP, prevV := 0.0, d.P[0][1]
		v = d.P[len(d.P)-1][1]
		for _, p := range d.P {
			if u <= p[0] {
				if p[0] > prevP {
					v = prevV + (u-prevP)/(p[0]-prevP)*(p[1]-prevV)
				} else {
					v = p[1]
				}
				break
			}
			prevP, prevV = p[0], p[1]
		}
	}
	if d.Min != 0 && v < d.Min {
		v = d.Min
	}
	if d.Max != 0 && v > d.Max {
		v = d.Max
	}
	return v
}

// MeanOf estimates the mean of d.
func (d Dist) MeanOf() float64 {
	r := rand.New(rand.NewPCG(1, 2))
	s := 0.0
	const n = 100000
	for i := 0; i < n; i++ {
		s += d.Sample(r)
	}
	return s / n
}

type Model struct {
	Note     string         `json:"note,omitempty"`
	Devices  DeviceModel    `json:"devices"`
	Mux      MuxModel       `json:"mux"`
	Net      []NetClass     `json:"net"`   // the users' networks
	Sites    []SiteClass    `json:"sites"` // how far the sites are
	Sessions []SessionClass `json:"sessions"`
	Observed map[string]any `json:"observed,omitempty"` // what the live server showed, for reference

	meanActive, meanIdle, meanOnline float64
}

type DeviceModel struct {
	Online      float64 `json:"online"`      // devices online at once, at scale 1
	OnlineSec   Dist    `json:"onlineSec"`   // how long a device stays online
	VanishShare float64 `json:"vanishShare"` // share of devices that drop off the network instead of closing
	ActiveSec   Dist    `json:"activeSec"`   // a spell of use (screen on)
	IdleSec     Dist    `json:"idleSec"`     // a pause between spells
	DownKBps    Dist    `json:"downKBps"`    // the device's download bandwidth
	UpKBps      Dist    `json:"upKBps"`
	// connections that never finish the handshake (the first packet lost on
	// the way, probes): per device per second, and how long until the
	// client or the server's handshake timeout ends them
	StallRate float64 `json:"stallRate"`
	StallSec  Dist    `json:"stallSec"`
}

// MuxModel is the client's Xray mux (Mux.Cool) setup.
type MuxModel struct {
	Concurrency     int     `json:"concurrency"`     // sessions at once on a mux connection
	XudpConcurrency int     `json:"xudpConcurrency"` // UDP sessions at once on an XUDP mux connection
	MaxConnection   int     `json:"maxConnection"`   // sessions over a connection's life (Xray: 128)
	CloseIdleShare  float64 `json:"closeIdleShare"`  // devices whose client closes idle mux connections (16 s checks); the rest leave it to the server (60 s checks)
}

// NetClass is one kind of user network, applied by the runner with netem on
// the source addresses of that class.
type NetClass struct {
	Name     string  `json:"name"`
	Share    float64 `json:"share"`
	RTTms    float64 `json:"rttMs"`
	JitterMs float64 `json:"jitterMs"`
	LossPct  float64 `json:"lossPct"`
}

// SiteClass is a group of site addresses at one distance.
type SiteClass struct {
	Name  string  `json:"name"`
	Share float64 `json:"share"`
	RTTms float64 `json:"rttMs"`
}

// SessionClass is one kind of connection a device makes through the core.
type SessionClass struct {
	Name       string    `json:"name"`
	UDP        bool      `json:"udp,omitempty"`
	Ports      []int     `json:"ports"`
	Weights    []float64 `json:"weights,omitempty"`
	AtConnect  int       `json:"atConnect,omitempty"`  // opened when the device comes online, reopened when they end
	ActiveRate float64   `json:"activeRate,omitempty"` // new sessions per second while the device is in use
	IdleRate   float64   `json:"idleRate,omitempty"`   // and while it is not
	Burst      Dist      `json:"burst"`                // sessions opened together each time (a page load); 0 = 1
	Every      Dist      `json:"every"`                // or: one every so many seconds while online, active or not
	Fresh      bool      `json:"fresh,omitempty"`      // on a new mux connection of its own, never reused (as a separate client core would)
	Exchanges  Dist      `json:"exchanges"`            // request/response pairs
	Gap        Dist      `json:"gap"`                  // seconds between them
	Req        Dist      `json:"req"`                  // bytes up per exchange
	Resp       Dist      `json:"resp"`                 // bytes down per exchange
	Think      Dist      `json:"think"`                // ms the site takes to answer
	Hold       Dist      `json:"hold"`                 // seconds the client keeps it after the last exchange
	SiteIdle   Dist      `json:"siteIdle"`             // seconds of quiet after which the site closes it (0 = never)
	Heartbeat  Dist      `json:"heartbeat"`            // seconds between client heartbeats while held (0 = none)
	PushEvery  Dist      `json:"pushEvery"`            // seconds between site pushes while held (0 = none)
	PushBytes  Dist      `json:"pushBytes"`
	DeadShare  float64   `json:"deadShare,omitempty"` // share sent to addresses that never answer
	DeadWait   Dist      `json:"deadWait"`            // seconds the client waits on those
	// UDP flows
	Life     Dist `json:"life"`     // seconds
	Pps      Dist `json:"pps"`      // datagrams per second up
	PktBytes Dist `json:"pktBytes"` // datagram size
	Replies  Dist `json:"replies"`  // datagrams back per datagram
}

func loadModel(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := &Model{}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m.Mux.MaxConnection == 0 {
		m.Mux.MaxConnection = 128
	}
	if m.Mux.Concurrency == 0 {
		m.Mux.Concurrency = 8
	}
	if m.Mux.XudpConcurrency == 0 {
		m.Mux.XudpConcurrency = 16
	}
	if m.Devices.Online <= 0 || len(m.Sessions) == 0 || len(m.Net) == 0 || len(m.Sites) == 0 {
		return nil, fmt.Errorf("%s: devices.online, net, sites and sessions are needed", path)
	}
	m.meanActive = m.Devices.ActiveSec.MeanOf()
	m.meanIdle = m.Devices.IdleSec.MeanOf()
	m.meanOnline = m.Devices.OnlineSec.MeanOf()
	return m, nil
}

func pickWeighted(r *rand.Rand, n int, weight func(int) float64) int {
	tot := 0.0
	for i := 0; i < n; i++ {
		tot += weight(i)
	}
	u := r.Float64() * tot
	for i := 0; i < n; i++ {
		u -= weight(i)
		if u <= 0 {
			return i
		}
	}
	return n - 1
}

// ------------------------------------------------------------ devices

// devProfile is what is fixed for a device while it is online.
type devProfile struct {
	online    float64 // seconds
	vanish    bool
	closeIdle bool
	net       int
	downBps   float64
	upBps     float64
}

func newProfile(m *Model, r *rand.Rand) devProfile {
	return devProfile{
		online:    m.Devices.OnlineSec.Sample(r),
		vanish:    r.Float64() < m.Devices.VanishShare,
		closeIdle: r.Float64() < m.Mux.CloseIdleShare,
		net:       pickWeighted(r, len(m.Net), func(i int) float64 { return m.Net[i].Share }),
		downBps:   m.Devices.DownKBps.Sample(r) * 1000,
		upBps:     m.Devices.UpKBps.Sample(r) * 1000,
	}
}

// arrivals draws the times (seconds after the device came online) at which
// the device opens sessions of each kind, switching between spells of use
// and pauses. AtConnect sessions are not included.
type arrivals struct {
	m        *Model
	r        *rand.Rand
	t, end   float64
	active   bool
	phaseEnd float64
}

func newArrivals(m *Model, r *rand.Rand, end float64) *arrivals {
	a := &arrivals{m: m, r: r, end: end}
	// start somewhere in a spell of use or a pause
	a.active = r.Float64() < m.meanActive/(m.meanActive+m.meanIdle)
	if a.active {
		a.phaseEnd = m.Devices.ActiveSec.Sample(r) * r.Float64()
	} else {
		a.phaseEnd = m.Devices.IdleSec.Sample(r) * r.Float64()
	}
	return a
}

func (a *arrivals) rate(c int) float64 {
	if a.active {
		return a.m.Sessions[c].ActiveRate
	}
	return a.m.Sessions[c].IdleRate
}

// next returns the next session start and its class, or ok=false once the
// device's time is up.
func (a *arrivals) next() (t float64, class int, ok bool) {
	for {
		total := 0.0
		for c := range a.m.Sessions {
			total += a.rate(c)
		}
		dt := math.Inf(1)
		if total > 0 {
			dt = a.r.ExpFloat64() / total
		}
		if a.t+dt < a.phaseEnd {
			a.t += dt
			if a.t >= a.end {
				return 0, 0, false
			}
			return a.t, pickWeighted(a.r, len(a.m.Sessions), a.rate), true
		}
		a.t = a.phaseEnd
		if a.t >= a.end {
			return 0, 0, false
		}
		a.active = !a.active
		if a.active {
			a.phaseEnd = a.t + a.m.Devices.ActiveSec.Sample(a.r)
		} else {
			a.phaseEnd = a.t + a.m.Devices.IdleSec.Sample(a.r)
		}
	}
}

// ------------------------------------------------------------ sessions

type step struct {
	gap   float64 // seconds after the previous exchange finished
	req   int
	resp  int
	think int // ms
}

// script is everything one session will do, drawn when it starts.
type script struct {
	class     int
	udp       bool
	port      int
	site      int // site class, -1 for an address that never answers
	steps     []step
	hold      float64 // seconds kept after the last exchange
	siteIdle  float64 // the site closes it after this much quiet (0 = never)
	heartbeat float64
	pushEvery float64
	pushBytes int
	deadWait  float64
	// UDP
	life    float64
	pps     float64
	pkt     int
	replies int
}

func makeScript(m *Model, r *rand.Rand, c int) script {
	sc := &m.Sessions[c]
	s := script{class: c, udp: sc.UDP}
	if len(sc.Ports) > 0 {
		s.port = sc.Ports[pickWeighted(r, len(sc.Ports), func(i int) float64 {
			if i < len(sc.Weights) {
				return sc.Weights[i]
			}
			return 1
		})]
	}
	s.site = pickWeighted(r, len(m.Sites), func(i int) float64 { return m.Sites[i].Share })
	if sc.DeadShare > 0 && r.Float64() < sc.DeadShare {
		s.site = -1
		s.deadWait = sc.DeadWait.Sample(r)
		return s
	}
	if sc.UDP {
		s.life = sc.Life.Sample(r)
		s.pps = sc.Pps.Sample(r)
		s.pkt = int(sc.PktBytes.Sample(r))
		s.replies = int(math.Round(sc.Replies.Sample(r)))
		return s
	}
	n := int(math.Round(sc.Exchanges.Sample(r)))
	for i := 0; i < n; i++ {
		st := step{req: int(sc.Req.Sample(r)), resp: int(sc.Resp.Sample(r)), think: int(sc.Think.Sample(r))}
		if i > 0 {
			st.gap = sc.Gap.Sample(r)
		}
		s.steps = append(s.steps, st)
	}
	s.hold = sc.Hold.Sample(r)
	s.siteIdle = sc.SiteIdle.Sample(r)
	s.heartbeat = sc.Heartbeat.Sample(r)
	s.pushEvery = sc.PushEvery.Sample(r)
	s.pushBytes = int(sc.PushBytes.Sample(r))
	return s
}

// estimate is how long the session lasts and what it carries, on a device
// with the given bandwidth and round trip, for the fitter.
func (s script) estimate(p devProfile, rttSec, siteRTT float64) (dur, down, up float64) {
	if s.site < 0 {
		return s.deadWait, 0, 0
	}
	if s.udp {
		sent := s.pps * s.life
		return s.life, sent * float64(s.replies*s.pkt), sent * float64(s.pkt)
	}
	t := rttSec + siteRTT // the mux New frame and the site's connect
	for _, st := range s.steps {
		t += st.gap + rttSec + siteRTT + float64(st.think)/1000 + float64(st.resp)/p.downBps + float64(st.req)/p.upBps
		down += float64(st.resp)
		up += float64(st.req + cmdHeaderLen)
	}
	hold := s.hold
	if s.siteIdle > 0 && (s.heartbeat == 0 || s.heartbeat > s.siteIdle) && s.siteIdle < hold {
		hold = s.siteIdle
	}
	if s.heartbeat > 0 {
		up += hold / s.heartbeat * 64
		down += hold / s.heartbeat * 64
	}
	if s.pushEvery > 0 {
		down += hold / s.pushEvery * float64(s.pushBytes)
	}
	return t + hold, down, up
}

// burst is how many sessions of class c open together.
func burst(m *Model, r *rand.Rand, c int) int {
	n := int(math.Round(m.Sessions[c].Burst.Sample(r)))
	if n < 1 {
		n = 1
	}
	return n
}

// residualOnline draws a stay length as found among devices online at a
// given moment: length-biased, so long stays turn up in proportion to how
// long they are.
func residualOnline(m *Model, r *rand.Rand) float64 {
	top := m.Devices.OnlineSec.Max
	if top <= 0 {
		top = 20 * m.meanOnline
	}
	for i := 0; i < 10000; i++ {
		l := m.Devices.OnlineSec.Sample(r)
		if r.Float64()*top < l {
			return l
		}
	}
	return m.meanOnline
}

// pickWorker is Xray's IncrementalWorkerPicker.pickInternal: take the first
// worker that is not full and swap it to the end of the list. nil when all
// are full (the caller then adds a new one at the end).
func pickWorker[W any](pool *[]W, full func(W) bool) (w W) {
	ws := *pool
	for idx := range ws {
		if !full(ws[idx]) {
			n := len(ws)
			if n > 1 && idx != n-1 {
				ws[n-1], ws[idx] = ws[idx], ws[n-1]
			}
			return ws[n-1]
		}
	}
	return w
}
