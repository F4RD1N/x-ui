//go:build linux

// Command xload loads xray VLESS inbounds (TCP, optionally with the HTTP
// header) with many connections, for comparing one core with several.
//
//	xload echo   -ports 41001-41016
//	xload client -inbound-ports 31000 -dst-ips 127.0.0.1-127.0.0.64 \
//	             -uuids uuids.txt -target 1.2.3.4 -target-ports 41001-41016 \
//	             -conns 500000 -dial-rate 20000 -http \
//	             -phases idle:0:45,light:10s:60,heavy:2s:60 -out result.json
//
// The client opens -conns connections through the inbounds to the echo
// server, each with one 64-byte message on the way up. Then, phase by phase,
// every connection sends a message at the phase's interval (jittered) and
// times the echo. Interval 0 holds the connections idle.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: xload echo|client [flags]")
		os.Exit(2)
	}
	raiseNofile()
	switch os.Args[1] {
	case "echo":
		echoMain(os.Args[2:])
	case "client":
		clientMain(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: xload echo|client [flags]")
		os.Exit(2)
	}
}

func raiseNofile() {
	lim := syscall.Rlimit{Cur: 4 << 20, Max: 4 << 20}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		lim = syscall.Rlimit{Cur: 1 << 20, Max: 1 << 20}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
}

func parsePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		a, b, ok := strings.Cut(part, "-")
		lo, _ := strconv.Atoi(a)
		hi := lo
		if ok {
			hi, _ = strconv.Atoi(b)
		}
		for p := lo; p <= hi && p > 0; p++ {
			out = append(out, p)
		}
	}
	return out
}

func parseIPs(s string) []string {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return strings.Split(s, ",")
	}
	lo, hi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	var out []string
	for x := binary.BigEndian.Uint32(lo); x <= binary.BigEndian.Uint32(hi); x++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, x)
		out = append(out, ip.String())
	}
	return out
}

// ------------------------------------------------------------ echo

func echoMain(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	host := fs.String("host", "0.0.0.0", "listen address")
	ports := fs.String("ports", "41001-41016", "ports")
	fs.Parse(args)
	var active atomic.Int64
	for _, p := range parsePorts(*ports) {
		ln, err := net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(p)))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				active.Add(1)
				go func() {
					defer active.Add(-1)
					defer c.Close()
					buf := make([]byte, 512)
					for {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
				}()
			}
		}()
	}
	for {
		time.Sleep(10 * time.Second)
		fmt.Fprintf(os.Stderr, "%s echo active=%d\n", time.Now().Format("15:04:05"), active.Load())
	}
}

// ------------------------------------------------------------ histogram

// Latency histogram: 4 buckets per power of two of microseconds.
const nBuckets = 4 * 30

func bucketOf(us int64) int {
	if us < 4 {
		if us < 0 {
			return 0
		}
		return int(us)
	}
	oct := 63 - bits.LeadingZeros64(uint64(us))
	sub := int((us >> (oct - 2)) & 3)
	b := oct*4 + sub
	if b >= nBuckets {
		b = nBuckets - 1
	}
	return b
}

// bucketUpper is the largest value in bucket b, in microseconds.
func bucketUpper(b int) float64 {
	if b < 4 {
		return float64(b)
	}
	oct, sub := b/4, b%4
	return float64((int64(4+sub+1) << (oct - 2)) - 1)
}

const nShards = 64

type hist struct {
	c [nShards][nBuckets]atomic.Uint64
}

func (h *hist) add(shard int, d time.Duration) {
	h.c[shard%nShards][bucketOf(d.Microseconds())].Add(1)
}

func (h *hist) percentiles(ps ...float64) ([]float64, uint64, float64) {
	var tot [nBuckets]uint64
	var n uint64
	for s := range h.c {
		for b := range h.c[s] {
			v := h.c[s][b].Load()
			tot[b] += v
			n += v
		}
	}
	out := make([]float64, len(ps))
	max := 0.0
	for b := nBuckets - 1; b >= 0; b-- {
		if tot[b] > 0 {
			max = bucketUpper(b) / 1000
			break
		}
	}
	if n == 0 {
		return out, 0, 0
	}
	for i, p := range ps {
		want := uint64(math.Ceil(p * float64(n)))
		var acc uint64
		for b := 0; b < nBuckets; b++ {
			acc += tot[b]
			if acc >= want {
				out[i] = bucketUpper(b) / 1000 // ms
				break
			}
		}
	}
	return out, n, max
}

// ------------------------------------------------------------ client

type phase struct {
	Name     string        `json:"name"`
	Interval time.Duration `json:"-"`
	Dur      time.Duration `json:"-"`
}

type phaseStats struct {
	sent, recv, timeouts, errs atomic.Int64
	h                          hist
	start, measureFrom, end    time.Time
}

var (
	phases     []phase
	stats      []*phaseStats
	curPhase   atomic.Int32 // -1 while connecting
	measuring  atomic.Bool
	phaseMu    sync.Mutex
	phaseCh    = make(chan struct{}) // closed when the phase changes
	doneCh     = make(chan struct{})
	connectH   hist
	estab      atomic.Int64
	dialFail   atomic.Int64
	hsFail     atomic.Int64
	dropped    atomic.Int64
	lastDialEr atomic.Value
)

func phaseChanged() <-chan struct{} {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return phaseCh
}

func setPhase(i int) {
	phaseMu.Lock()
	curPhase.Store(int32(i))
	close(phaseCh)
	phaseCh = make(chan struct{})
	phaseMu.Unlock()
}

func parsePhases(s string) []phase {
	var out []phase
	for _, p := range strings.Split(s, ",") {
		f := strings.Split(p, ":")
		if len(f) != 3 {
			fmt.Fprintln(os.Stderr, "phase must be name:interval:seconds:", p)
			os.Exit(2)
		}
		var iv time.Duration
		if f[1] != "0" {
			iv, _ = time.ParseDuration(f[1])
		}
		secs, _ := strconv.Atoi(f[2])
		out = append(out, phase{Name: f[0], Interval: iv, Dur: time.Duration(secs) * time.Second})
	}
	return out
}

type clientCfg struct {
	inboundPorts []int
	dstIPs       []string
	uuids        [][16]byte
	target       net.IP
	targetPorts  []int
	http         bool
	size         int
	readTimeout  time.Duration
}

var httpRequest = []byte("GET / HTTP/1.1\r\nHost: www.bing.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nPragma: no-cache\r\n\r\n")

func clientMain(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	inPorts := fs.String("inbound-ports", "31000", "inbound ports")
	dstIPs := fs.String("dst-ips", "127.0.0.1-127.0.0.64", "addresses to reach the inbounds on")
	uuidFile := fs.String("uuids", "uuids.txt", "client ids, one per line")
	target := fs.String("target", "", "echo server address (must be routable by the core)")
	tPorts := fs.String("target-ports", "41001-41016", "echo server ports")
	conns := fs.Int("conns", 10000, "connections")
	rate := fs.Int("dial-rate", 10000, "new connections per second")
	useHTTP := fs.Bool("http", true, "send the TCP HTTP header")
	size := fs.Int("size", 64, "message size")
	ph := fs.String("phases", "idle:0:30,light:10s:60,heavy:2s:60", "name:interval:seconds,...")
	warm := fs.Duration("warmup", 10*time.Second, "time at the start of a phase not measured")
	out := fs.String("out", "", "write the result JSON here")
	rampLimit := fs.Duration("ramp-timeout", 180*time.Second, "give up connecting after this")
	fs.Parse(args)

	cfg := &clientCfg{
		inboundPorts: parsePorts(*inPorts), dstIPs: parseIPs(*dstIPs), target: net.ParseIP(*target).To4(),
		targetPorts: parsePorts(*tPorts), http: *useHTTP, size: *size, readTimeout: 15 * time.Second,
	}
	if cfg.target == nil {
		fmt.Fprintln(os.Stderr, "-target must be an IPv4 address")
		os.Exit(2)
	}
	data, err := os.ReadFile(*uuidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, line := range strings.Fields(string(data)) {
		b, err := hex.DecodeString(strings.ReplaceAll(line, "-", ""))
		if err == nil && len(b) == 16 {
			var u [16]byte
			copy(u[:], b)
			cfg.uuids = append(cfg.uuids, u)
		}
	}
	if len(cfg.uuids) == 0 {
		fmt.Fprintln(os.Stderr, "no uuids")
		os.Exit(1)
	}
	phases = parsePhases(*ph)
	for range phases {
		stats = append(stats, &phaseStats{})
	}
	curPhase.Store(-1)

	// Connect at the given rate.
	t0 := time.Now()
	var wg sync.WaitGroup
	tick := time.Second / time.Duration(*rate)
	go progress()
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runConn(cfg, id)
		}(i)
		if tick > 0 && i%100 == 99 {
			next := t0.Add(time.Duration(i+1) * tick)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}
	for estab.Load()+dialFail.Load()+hsFail.Load() < int64(*conns) && time.Since(t0) < *rampLimit {
		time.Sleep(100 * time.Millisecond)
	}
	ramp := time.Since(t0)
	fmt.Fprintf(os.Stderr, "ramp done in %.1fs: established=%d dialFail=%d handshakeFail=%d\n", ramp.Seconds(), estab.Load(), dialFail.Load(), hsFail.Load())
	type phaseOut struct {
		Name            string             `json:"name"`
		IntervalSec     float64            `json:"intervalSec"`
		StartUnix       float64            `json:"startUnix"`
		MeasureFromUnix float64            `json:"measureFromUnix"`
		EndUnix         float64            `json:"endUnix"`
		Conns           int64              `json:"conns"`
		OfferedPerSec   float64            `json:"offeredPerSec"`
		SentPerSec      float64            `json:"sentPerSec"`
		RecvPerSec      float64            `json:"recvPerSec"`
		Timeouts        int64              `json:"timeouts"`
		Errors          int64              `json:"errors"`
		Pct             map[string]float64 `json:"rttMs"`
	}
	result := map[string]any{
		"conns": *conns, "rampSec": ramp.Seconds(), "established": estab.Load(),
		"dialFail": dialFail.Load(), "handshakeFail": hsFail.Load(),
	}
	if e, ok := lastDialEr.Load().(string); ok {
		result["lastError"] = e
	}
	cp, cn, cmax := connectH.percentiles(0.5, 0.99)
	result["connectMs"] = map[string]float64{"p50": cp[0], "p99": cp[1], "max": cmax, "n": float64(cn)}

	var outs []phaseOut
	for i, p := range phases {
		st := stats[i]
		st.start = time.Now()
		measuring.Store(false)
		setPhase(i)
		w := *warm
		if w > p.Dur/2 {
			w = p.Dur / 2
		}
		time.Sleep(w)
		st.measureFrom = time.Now()
		measuring.Store(true)
		time.Sleep(p.Dur - w)
		measuring.Store(false)
		st.end = time.Now()
		secs := st.end.Sub(st.measureFrom).Seconds()
		live := estab.Load() - dropped.Load()
		o := phaseOut{Name: p.Name, IntervalSec: p.Interval.Seconds(), Conns: live,
			StartUnix: float64(st.start.UnixNano()) / 1e9, MeasureFromUnix: float64(st.measureFrom.UnixNano()) / 1e9, EndUnix: float64(st.end.UnixNano()) / 1e9,
			SentPerSec: float64(st.sent.Load()) / secs, RecvPerSec: float64(st.recv.Load()) / secs,
			Timeouts: st.timeouts.Load(), Errors: st.errs.Load()}
		if p.Interval > 0 {
			o.OfferedPerSec = float64(live) / p.Interval.Seconds()
		}
		pc, n, max := st.h.percentiles(0.5, 0.9, 0.99, 0.999)
		o.Pct = map[string]float64{"p50": pc[0], "p90": pc[1], "p99": pc[2], "p999": pc[3], "max": max, "n": float64(n)}
		outs = append(outs, o)
		b, _ := json.Marshal(o)
		fmt.Fprintf(os.Stderr, "phase %s\n", b)
	}
	result["phases"] = outs
	close(doneCh)
	b, _ := json.MarshalIndent(result, "", "  ")
	if *out != "" {
		os.WriteFile(*out, b, 0o644)
	}
	fmt.Println(string(b))
	// Connections close as their goroutines see done; do not wait for all.
	time.Sleep(2 * time.Second)
}

func progress() {
	var lastSent, lastRecv int64
	for {
		time.Sleep(5 * time.Second)
		var s, r int64
		for _, st := range stats {
			s += st.sent.Load()
			r += st.recv.Load()
		}
		fmt.Fprintf(os.Stderr, "%s phase=%d estab=%d dialFail=%d hsFail=%d dropped=%d sent/s=%d recv/s=%d\n",
			time.Now().Format("15:04:05"), curPhase.Load(), estab.Load(), dialFail.Load(), hsFail.Load(), dropped.Load(), (s-lastSent)/5, (r-lastRecv)/5)
		lastSent, lastRecv = s, r
	}
}

var errBadResponse = errors.New("bad response")

func runConn(cfg *clientCfg, id int) {
	port := cfg.inboundPorts[id%len(cfg.inboundPorts)]
	ip := cfg.dstIPs[(id/len(cfg.inboundPorts))%len(cfg.dstIPs)]
	d := net.Dialer{Timeout: 20 * time.Second}
	c, err := d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		dialFail.Add(1)
		lastDialEr.Store(err.Error())
		return
	}
	defer c.Close()

	// HTTP request header, VLESS request header, first message.
	tport := cfg.targetPorts[id%len(cfg.targetPorts)]
	uuid := cfg.uuids[id%len(cfg.uuids)]
	var pkt bytes.Buffer
	if cfg.http {
		pkt.Write(httpRequest)
	}
	pkt.WriteByte(0) // version
	pkt.Write(uuid[:])
	pkt.WriteByte(0) // addons
	pkt.WriteByte(1) // TCP
	pkt.WriteByte(byte(tport >> 8))
	pkt.WriteByte(byte(tport))
	pkt.WriteByte(1) // IPv4
	pkt.Write(cfg.target)
	msg := make([]byte, cfg.size)
	echo := make([]byte, cfg.size)
	stamp := func() { binary.LittleEndian.PutUint64(msg, uint64(time.Now().UnixNano())) }
	stamp()
	pkt.Write(msg)
	t0 := time.Now()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := c.Write(pkt.Bytes()); err != nil {
		hsFail.Add(1)
		lastDialEr.Store(err.Error())
		return
	}
	br := bufio.NewReaderSize(c, 256)
	if cfg.http {
		line, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
			hsFail.Add(1)
			if err != nil {
				lastDialEr.Store("http response: " + err.Error())
			}
			return
		}
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				hsFail.Add(1)
				return
			}
			if line == "\r\n" {
				break
			}
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		hsFail.Add(1)
		lastDialEr.Store("vless response: " + err.Error())
		return
	}
	if hdr[1] > 0 {
		if _, err := br.Discard(int(hdr[1])); err != nil {
			hsFail.Add(1)
			return
		}
	}
	if _, err := io.ReadFull(br, echo); err != nil || !bytes.Equal(echo, msg) {
		hsFail.Add(1)
		if err != nil {
			lastDialEr.Store("first echo: " + err.Error())
		}
		return
	}
	connectH.add(id, time.Since(t0))
	estab.Add(1)
	c.SetDeadline(time.Time{})

	rng := rand.New(rand.NewPCG(uint64(id), uint64(time.Now().UnixNano())))
	for {
		changed := phaseChanged()
		p := int(curPhase.Load())
		if p < 0 || phases[p].Interval == 0 {
			select {
			case <-changed:
				continue
			case <-doneCh:
				return
			}
		}
		iv := phases[p].Interval
		// Spread sends across the interval: uniform 0.5x..1.5x.
		wait := time.Duration((0.5 + rng.Float64()) * float64(iv))
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-changed:
			t.Stop()
			continue
		case <-doneCh:
			t.Stop()
			return
		}
		st := stats[p]
		meas := measuring.Load()
		stamp()
		c.SetWriteDeadline(time.Now().Add(cfg.readTimeout))
		if _, err := c.Write(msg); err != nil {
			if meas {
				st.errs.Add(1)
			}
			dropped.Add(1)
			return
		}
		if meas {
			st.sent.Add(1)
		}
		c.SetReadDeadline(time.Now().Add(cfg.readTimeout))
		if _, err := io.ReadFull(br, echo); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if meas {
					st.timeouts.Add(1)
				}
			} else if meas {
				st.errs.Add(1)
			}
			dropped.Add(1)
			return
		}
		if meas && measuring.Load() {
			st.recv.Add(1)
			st.h.add(id, time.Duration(time.Now().UnixNano()-int64(binary.LittleEndian.Uint64(echo))))
		}
	}
}
