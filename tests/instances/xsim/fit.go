//go:build linux

package main

// xsim fit: run the model in virtual time — devices, their sessions, the
// client's mux pool and the server's mux idle rule — and measure what
// sim/observe.py measures on a live server, side by side with an
// observe.json. Used to fit sim/model.json; nothing touches the network.

import (
	"container/heap"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
)

type vworker struct {
	dev         *vdev
	xudp        bool
	born        float64
	size, count int
	closed      bool
	cSize, cCnt int // client-side snapshot at the last 16 s check
	sSize, sCnt int // server-side snapshot at the last 60 s check
	closedBy    string
	sessions    map[*vsess]bool
	vanished    bool // its device dropped off the network
}

// serverConnIdle is the core's policy connIdle on the live server.
const serverConnIdle = 180.0

type vsess struct {
	w         *vworker
	start     float64
	end       float64
	done      bool
	dead, udp bool
	atConnect bool
	class     int
}

type vdev struct {
	id       int
	p        devProfile
	arr      *arrivals
	t0       float64
	gone     bool
	tcp, udp []*vworker
	fresh    []*vworker
}

type event struct {
	t    float64
	kind int
	seq  uint64
	dev  *vdev
	w    *vworker
	s    *vsess
	c    int
}

const (
	evArrive = iota
	evDepart
	evSessStart
	evSessEnd
	evClientTick
	evServerTick
	evSample
	evConnectSess
	evBurstSess
	evStall
	evStallEnd
	evEvery
)

type evHeap []*event

func (h evHeap) Len() int { return len(h) }
func (h evHeap) Less(i, j int) bool {
	if h[i].t != h[j].t {
		return h[i].t < h[j].t
	}
	return h[i].seq < h[j].seq
}
func (h evHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *evHeap) Push(x any)   { *h = append(*h, x.(*event)) }
func (h *evHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

type fitSim struct {
	m       *Model
	r       *rand.Rand
	h       evHeap
	seq     uint64
	now     float64
	devs    int
	scale   float64
	meanOn  float64
	warm    float64
	window  float64 // the observe-style window, from warm
	measure float64 // the averaging span, from warm
	phase   float64 // of the 2 s snapshots

	// stats
	samples                         int
	sumMux, sumTCP, sumUDP, sumDevs float64
	sumIdleMux                      float64
	muxBirths, dials, deadDials     int
	stalls                          int
	udpBirths                       int
	down, up                        float64
	muxLife, tcpLife                []float64
	initMux, initTCP                map[any]bool
	initMuxGone, initTCPGone        []float64
	devsAtW0                        int
	devsNew                         int
	closedBy                        map[string]int
	sessPerMux                      []float64
	standingMux, standingTCP        int
	standingUDP, standingDevs       int
}

// observe.py looks every ~2 s: a connection is seen if a snapshot falls in
// its life, and its lifetime is measured between snapshots.
const samplePeriod = 2.0

func (f *fitSim) seenLife(start, end float64) (float64, bool) {
	a := math.Ceil((start-f.phase)/samplePeriod)*samplePeriod + f.phase
	b := math.Ceil((end-f.phase)/samplePeriod)*samplePeriod + f.phase
	return b - a, b > a
}

func (f *fitSim) push(e *event) {
	f.seq++
	e.seq = f.seq
	heap.Push(&f.h, e)
}

func (f *fitSim) inWindow(t float64) bool { return t >= f.warm && t < f.warm+f.window }
func (f *fitSim) inMeasure(t float64) bool {
	return t >= f.warm && t < f.warm+f.measure
}

func (f *fitSim) arrive(t float64, residual bool) {
	d := &vdev{id: f.devs, t0: t}
	f.devs++
	d.p = newProfile(f.m, f.r)
	life := d.p.online
	if residual {
		// devices already online at the start: what is left of their time,
		// with long stays as likely as they are among devices online at once
		d.p.online = residualOnline(f.m, f.r)
		life = d.p.online * f.r.Float64()
	}
	f.push(&event{t: t + life, kind: evDepart, dev: d})
	d.arr = newArrivals(f.m, f.r, life)
	if nt, c, ok := d.arr.next(); ok {
		f.push(&event{t: t + nt, kind: evSessStart, dev: d, c: c})
	}
	for c, sc := range f.m.Sessions {
		if sc.Every.Type != "" || sc.Every.V > 0 {
			f.push(&event{t: t + f.r.Float64()*sc.Every.Sample(f.r), kind: evEvery, dev: d, c: c})
		}
	}
	if f.m.Devices.StallRate > 0 {
		f.push(&event{t: t + f.r.ExpFloat64()/f.m.Devices.StallRate, kind: evStall, dev: d})
	}
	for c, sc := range f.m.Sessions {
		for i := 0; i < sc.AtConnect; i++ {
			f.push(&event{t: t + f.r.Float64()*3, kind: evConnectSess, dev: d, c: c})
		}
	}
	f.standingDevs++
	if f.inWindow(t) {
		f.devsNew++
	}
}

func (f *fitSim) pick(d *vdev, xudp bool) *vworker {
	pool := &d.tcp
	conc := f.m.Mux.Concurrency
	if xudp {
		pool = &d.udp
		conc = f.m.Mux.XudpConcurrency
	}
	// Xray's IncrementalWorkerPicker: the first worker that is not full,
	// swapped to the end of the list; a new one when all are full.
	if w := pickWorker(pool, func(w *vworker) bool {
		return w.closed || w.size >= conc || w.count >= f.m.Mux.MaxConnection
	}); w != nil {
		return w
	}
	live := (*pool)[:0]
	for _, w := range *pool {
		if !w.closed {
			live = append(live, w)
		}
	}
	*pool = live
	w := f.newWorker(d, xudp)
	*pool = append(*pool, w)
	return w
}

func (f *fitSim) newWorker(d *vdev, xudp bool) *vworker {
	w := &vworker{dev: d, xudp: xudp, born: f.now, sessions: map[*vsess]bool{}}
	f.standingMux++
	if f.inMeasure(f.now) {
		f.muxBirths++
	}
	if d.p.closeIdle {
		f.push(&event{t: f.now + 16, kind: evClientTick, w: w})
	}
	f.push(&event{t: f.now + 60, kind: evServerTick, w: w})
	return w
}

func (f *fitSim) closeWorker(w *vworker, by string) {
	if w.closed {
		return
	}
	w.closed = true
	w.closedBy = by
	f.closedBy[by]++
	f.standingMux--
	if l, ok := f.seenLife(w.born, f.now); ok && f.inWindow(w.born) && f.inWindow(f.now) {
		f.muxLife = append(f.muxLife, l)
	}
	if f.initMux[w] {
		f.initMuxGone = append(f.initMuxGone, f.now-f.warm)
		delete(f.initMux, w)
	}
	for s := range w.sessions {
		f.endSession(s)
	}
}

func (f *fitSim) endSession(s *vsess) {
	if s.done {
		return
	}
	s.done = true
	w := s.w
	delete(w.sessions, s)
	w.size--
	switch {
	case s.udp:
		f.standingUDP--
	case !s.dead:
		f.standingTCP--
		if l, ok := f.seenLife(s.start, f.now); ok && f.inWindow(s.start) && f.inWindow(f.now) {
			f.tcpLife = append(f.tcpLife, l)
		}
		if f.initTCP[s] {
			f.initTCPGone = append(f.initTCPGone, f.now-f.warm)
			delete(f.initTCP, s)
		}
	}
	if s.atConnect && !s.w.dev.gone && !s.w.vanished {
		f.push(&event{t: f.now + 1 + f.r.Float64()*4, kind: evConnectSess, dev: s.w.dev, c: s.class})
	}
}

func (f *fitSim) startSession(d *vdev, c int, atConnect bool) {
	if d.gone {
		return
	}
	sc := makeScript(f.m, f.r, c)
	var w *vworker
	if f.m.Sessions[c].Fresh {
		w = f.newWorker(d, sc.udp)
		d.fresh = append(d.fresh, w)
	} else {
		w = f.pick(d, sc.udp)
	}
	s := &vsess{w: w, start: f.now, dead: sc.site < 0, udp: sc.udp, atConnect: atConnect, class: c}
	w.sessions[s] = true
	w.size++
	w.count++
	rtt := f.m.Net[d.p.net].RTTms / 1000
	siteRTT := 0.0
	if sc.site >= 0 {
		siteRTT = f.m.Sites[sc.site].RTTms / 1000
	}
	dur, down, up := sc.estimate(d.p, rtt, siteRTT)
	if dur > d.p.online*4 && atConnect {
		dur = d.p.online * 4
	}
	s.end = f.now + dur
	if f.inMeasure(f.now) {
		if sc.udp {
			f.udpBirths++
		} else {
			f.dials++
			if s.dead {
				f.deadDials++
			}
		}
		f.down += down
		f.up += up
	}
	switch {
	case s.udp:
		f.standingUDP++
	case !s.dead:
		f.standingTCP++
	}
	f.push(&event{t: s.end, kind: evSessEnd, s: s})
}

// idleCheck is Xray's SessionManager.CloseIfNoSessionAndIdle: close when
// there was no session at the last check and nothing came or went since.
func idleCheck(size int, snapSize, snapCnt *int, count int) bool {
	close := size == 0 && *snapSize == 0 && *snapCnt == count
	*snapSize, *snapCnt = size, count
	return close
}

func (f *fitSim) run(total float64) {
	initial := int(f.m.Devices.Online * f.scale)
	for i := 0; i < initial; i++ {
		f.arrive(0, true)
	}
	rate := f.m.Devices.Online * f.scale / f.meanOn
	f.push(&event{t: f.r.ExpFloat64() / rate, kind: evArrive})
	f.push(&event{t: f.warm, kind: evSample})
	for f.h.Len() > 0 {
		e := heap.Pop(&f.h).(*event)
		if e.t > total {
			break
		}
		f.now = e.t
		switch e.kind {
		case evArrive:
			f.arrive(f.now, false)
			f.push(&event{t: f.now + f.r.ExpFloat64()/rate, kind: evArrive})
		case evDepart:
			d := e.dev
			d.gone = true
			f.standingDevs--
			for _, w := range append(append(append([]*vworker{}, d.tcp...), d.udp...), d.fresh...) {
				if !d.p.vanish {
					f.closeWorker(w, "device left")
					continue
				}
				// The device dropped off the network: the server keeps its
				// connections until each session goes quiet for the core's
				// connIdle, then closes the mux connection on its 60 s check.
				w.vanished = true
				for s := range w.sessions {
					if s.end > f.now+serverConnIdle {
						s.end = f.now + serverConnIdle
						f.push(&event{t: s.end, kind: evSessEnd, s: s})
					}
				}
			}
		case evSessStart:
			d := e.dev
			if d.gone {
				break
			}
			f.startSession(d, e.c, false)
			for i := burst(f.m, f.r, e.c) - 1; i > 0; i-- {
				f.push(&event{t: f.now + f.r.Float64()*0.3, kind: evBurstSess, dev: d, c: e.c})
			}
			if nt, c, ok := d.arr.next(); ok {
				f.push(&event{t: d.t0 + nt, kind: evSessStart, dev: d, c: c})
			}
		case evConnectSess:
			f.startSession(e.dev, e.c, true)
		case evBurstSess:
			f.startSession(e.dev, e.c, false)
		case evEvery:
			if e.dev.gone {
				break
			}
			f.startSession(e.dev, e.c, false)
			f.push(&event{t: f.now + f.m.Sessions[e.c].Every.Sample(f.r), kind: evEvery, dev: e.dev, c: e.c})
		case evStall:
			d := e.dev
			if d.gone {
				break
			}
			life := f.m.Devices.StallSec.Sample(f.r)
			f.standingMux++
			if f.inMeasure(f.now) {
				f.muxBirths++
				f.stalls++
			}
			f.push(&event{t: f.now + life, kind: evStallEnd, c: int(f.now * 1000)})
			f.push(&event{t: f.now + f.r.ExpFloat64()/f.m.Devices.StallRate, kind: evStall, dev: d})
		case evStallEnd:
			f.standingMux--
			born := float64(e.c) / 1000
			if l, ok := f.seenLife(born, f.now); ok && f.inWindow(born) && f.inWindow(f.now) {
				f.muxLife = append(f.muxLife, l)
			}
		case evSessEnd:
			if !e.s.done && f.now >= e.s.end-1e-9 {
				f.endSession(e.s)
			}
		case evClientTick:
			w := e.w
			if w.closed || w.vanished {
				break
			}
			if idleCheck(w.size, &w.cSize, &w.cCnt, w.count) {
				f.closeWorker(w, "client idle")
			} else {
				f.push(&event{t: f.now + 16, kind: evClientTick, w: w})
			}
		case evServerTick:
			w := e.w
			if w.closed {
				break
			}
			if idleCheck(w.size, &w.sSize, &w.sCnt, w.count) {
				f.closeWorker(w, "server idle")
			} else {
				f.push(&event{t: f.now + 60, kind: evServerTick, w: w})
			}
		case evSample:
			if f.samples == 0 {
				// the cohort standing at the start of the window
				f.initMux, f.initTCP = map[any]bool{}, map[any]bool{}
				f.devsAtW0 = f.standingDevs
			}
			f.samples++
			f.sumMux += float64(f.standingMux)
			f.sumTCP += float64(f.standingTCP)
			f.sumUDP += float64(f.standingUDP)
			f.sumDevs += float64(f.standingDevs)
			if f.now+1 < f.warm+f.measure {
				f.push(&event{t: f.now + 1, kind: evSample})
			}
		}
		if f.samples == 1 && f.initMux != nil && len(f.initMux) == 0 && f.now == f.warm {
			f.snapshotCohort()
		}
	}
}

// snapshotCohort is called once, at the start of the window; it records
// which mux connections and sessions are standing then. The event loop does
// not keep a global list, so walk the pending session ends.
func (f *fitSim) snapshotCohort() {
	for _, e := range f.h {
		if e.kind == evSessEnd && !e.s.done && !e.s.dead && !e.s.udp {
			f.initTCP[e.s] = true
		}
		if e.kind == evServerTick && !e.w.closed {
			f.initMux[e.w] = true
		}
	}
}

var lifeEdges = []float64{0, 2, 5, 10, 20, 30, 60, 120, 180, 240}

func shares(v []float64, edges []float64) []float64 {
	c := make([]float64, len(edges))
	for _, x := range v {
		i := sort.SearchFloat64s(edges, x+1e-9) - 1
		if i < 0 {
			i = 0
		}
		c[i]++
	}
	n := float64(len(v))
	for i := range c {
		if n > 0 {
			c[i] /= n
		}
	}
	return c
}

func quantile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[int(p*float64(len(s)-1))]
}

func fitMain(args []string) {
	fs := flag.NewFlagSet("fit", flag.ExitOnError)
	modelPath := fs.String("model", "model.json", "model")
	obsPath := fs.String("observed", "", "observe.json from the live server, to compare with")
	scale := fs.Float64("scale", 1, "devices relative to the model's online count")
	warm := fs.Float64("warm", 1200, "seconds simulated before measuring")
	measure := fs.Float64("measure", 600, "seconds measured")
	seed := fs.Uint64("seed", 1, "random seed")
	asJSON := fs.Bool("json", false, "print the numbers as JSON")
	fs.Parse(args)
	m, err := loadModel(*modelPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f := &fitSim{m: m, r: rand.New(rand.NewPCG(*seed, 7)), scale: *scale, warm: *warm, window: 300, measure: *measure,
		meanOn: m.meanOnline, closedBy: map[string]int{}, phase: rand.New(rand.NewPCG(*seed, 9)).Float64() * samplePeriod}
	if f.measure < f.window {
		f.measure = f.window
	}
	f.run(*warm + f.measure + 1)
	span := f.measure
	n := float64(f.samples)
	res := map[string]any{
		"devices":           f.sumDevs / n,
		"mux_standing":      f.sumMux / n,
		"mux_births_per_s":  float64(f.muxBirths) / span,
		"stalls_per_s":      float64(f.stalls) / span,
		"tcp_standing":      f.sumTCP / n,
		"udp_standing":      f.sumUDP / n,
		"dials_per_s":       float64(f.dials) / span,
		"dead_dials_per_s":  float64(f.deadDials) / span,
		"udp_births_per_s":  float64(f.udpBirths) / span,
		"sessions_per_mux":  (f.sumTCP + f.sumUDP) / f.sumMux,
		"mux_per_device":    f.sumMux / f.sumDevs,
		"down_MBps":         f.down / span / 1e6,
		"up_MBps":           f.up / span / 1e6,
		"mux_life_shares":   shares(f.muxLife, lifeEdges),
		"tcp_life_shares":   shares(f.tcpLife, lifeEdges),
		"mux_life_p":        []float64{quantile(f.muxLife, .1), quantile(f.muxLife, .25), quantile(f.muxLife, .5), quantile(f.muxLife, .75), quantile(f.muxLife, .9)},
		"tcp_life_p":        []float64{quantile(f.tcpLife, .1), quantile(f.tcpLife, .25), quantile(f.tcpLife, .5), quantile(f.tcpLife, .75), quantile(f.tcpLife, .9)},
		"mux_closed_by":     f.closedBy,
		"devices_new_300s":  f.devsNew,
		"devices_at_window": f.devsAtW0,
		"init_mux_gone_300": float64(len(f.initMuxGone)),
		"init_tcp_gone_300": float64(len(f.initTCPGone)),
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", " ")
		fmt.Println(string(b))
		return
	}
	var obs map[string]any
	if *obsPath != "" {
		b, err := os.ReadFile(*obsPath)
		if err == nil {
			json.Unmarshal(b, &obs)
		}
	}
	get := func(path ...string) any {
		var cur any = obs
		for _, p := range path {
			mm, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = mm[p]
		}
		return cur
	}
	num := func(v any) float64 {
		if x, ok := v.(float64); ok {
			return x
		}
		return math.NaN()
	}
	histShares := func(v any) []float64 {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		hh, _ := mm["hist"].(map[string]any)
		cs, _ := hh["counts"].([]any)
		tot := 0.0
		for _, c := range cs {
			tot += num(c)
		}
		out := make([]float64, len(cs))
		for i, c := range cs {
			out[i] = num(c) / tot
		}
		return out
	}
	o := map[string]float64{}
	if obs != nil {
		o["mux_standing"] = num(get("conns", "in_now", "mean"))
		o["tcp_standing"] = num(get("conns", "out_now", "mean"))
		o["mux_births_per_s"] = num(get("kernel_rates", "Tcp.PassiveOpens"))
		o["dials_per_s"] = num(get("kernel_rates", "Tcp.ActiveOpens"))
		o["dead_dials_per_s"] = num(get("kernel_rates", "Tcp.AttemptFails"))
		o["devices"] = num(get("conns", "client_ips_at_start"))
		o["devices_new_300s"] = num(get("conns", "client_ips_seen")) - o["devices"]
		if u, ok := get("udp").([]any); ok && len(u) > 0 {
			s := 0.0
			for _, x := range u {
				s += num(x.(map[string]any)["total"])
			}
			o["udp_standing"] = s / float64(len(u))
		}
		o["down_MBps"] = num(get("traffic", "in", "total_down_Bps_per_sample")) / 1e6
		o["up_MBps"] = num(get("traffic", "in", "total_up_Bps_per_sample")) / 1e6
		o["sessions_per_mux"] = (o["tcp_standing"] + o["udp_standing"]) / o["mux_standing"]
		o["mux_per_device"] = o["mux_standing"] / o["devices"]
	}
	keys := []string{"devices", "devices_new_300s", "mux_standing", "mux_births_per_s", "mux_per_device", "tcp_standing", "dials_per_s",
		"dead_dials_per_s", "udp_standing", "sessions_per_mux", "down_MBps", "up_MBps"}
	fmt.Printf("%-20s %12s %12s\n", "", "model", "observed")
	for _, k := range keys {
		mv := 0.0
		switch v := res[k].(type) {
		case float64:
			mv = v
		case int:
			mv = float64(v)
		}
		ov, ok := o[k]
		os := ""
		if ok && !math.IsNaN(ov) {
			os = fmt.Sprintf("%12.1f", ov*f.scale)
		}
		fmt.Printf("%-20s %12.1f %s\n", k, mv, os)
	}
	fmtShares := func(v []float64) string {
		var b strings.Builder
		for _, x := range v {
			fmt.Fprintf(&b, "%5.0f", x*100)
		}
		return b.String()
	}
	fmt.Printf("\nlifetime shares, %% per bin %v\n", lifeEdges)
	fmt.Printf("%-12s %s\n", "mux model", fmtShares(res["mux_life_shares"].([]float64)))
	if obs != nil {
		fmt.Printf("%-12s %s\n", "mux live", fmtShares(histShares(get("conns", "lifetime_in"))))
	}
	fmt.Printf("%-12s %s\n", "tcp model", fmtShares(res["tcp_life_shares"].([]float64)))
	if obs != nil {
		fmt.Printf("%-12s %s\n", "tcp live", fmtShares(histShares(get("conns", "lifetime_out"))))
	}
	fmt.Printf("\nmux lifetime p10/25/50/75/90 %v\ntcp lifetime p10/25/50/75/90 %v\n", res["mux_life_p"], res["tcp_life_p"])
	if obs != nil {
		lp := func(k string) []float64 {
			var out []float64
			for _, p := range []string{"p10", "p25", "p50", "p75", "p90"} {
				out = append(out, math.Round(num(get("conns", k, p))*10)/10)
			}
			return out
		}
		fmt.Printf("live mux     %v\nlive tcp     %v\n", lp("lifetime_in"), lp("lifetime_out"))
	}
	initIn := num(get("conns", "initial_in"))
	fmt.Printf("\nstanding mux gone within 300 s: model %.0f%%", float64(len(f.initMuxGone))/math.Max(1, float64(len(f.initMuxGone)+len(f.initMux)))*100)
	if obs != nil && initIn > 0 {
		s := 0.0
		if hh, ok := get("conns", "initial_in_gone_at").(map[string]any); ok {
			for _, c := range hh["counts"].([]any) {
				s += num(c)
			}
		}
		fmt.Printf(", live %.0f%%", s/initIn*100)
	}
	fmt.Printf("\nmux closed by: %v\n", f.closedBy)
}
