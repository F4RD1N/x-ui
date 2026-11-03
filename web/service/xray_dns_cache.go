package service

// Users' DNS goes to this server's DNS cache.
//
// A user's query to any DNS server (port 53, UDP or TCP) is answered by the
// cache "x-ui dns" runs at 127.0.0.1 instead of leaving this server. Someone
// sweeping the internet for open resolvers through the VPN then reaches no
// one -- such sweeps put a server's IP on scanner and abuse lists -- and the
// cache can refuse names that serve only malware, which infected devices
// look up to call home ("x-ui anti-abuse" gives it that list). Queries of
// every type reach the cache unchanged.
//
// It is on while the cache is: "x-ui dns" keeps its state in dnsCacheState,
// and the cache must answer. The core follows when that changes: "x-ui dns
// on" and "off" start it again, and CheckDNSCache does when the cache stops
// or comes back by itself.

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// dnsCacheTag names the outbound and the routing rule; x-ui.sh looks for it
// in the running config.
const dnsCacheTag = "xui-dns-cache"

// dnsCacheAddr is where "x-ui dns" runs the cache.
const dnsCacheAddr = "127.0.0.1:53"

var (
	// dnsCacheState is the directory "x-ui dns" keeps while the cache is on.
	dnsCacheState = "/etc/x-ui/dns"
	// dnsCacheProbe says whether the cache answers.
	dnsCacheProbe = probeDNSCache
	// dnsCacheTries is how many times, half a second apart, a config build
	// asks the cache.
	dnsCacheTries = 3
)

// dnsCacheStateOn says whether "x-ui dns" has the cache on.
func dnsCacheStateOn() bool {
	fi, err := os.Stat(dnsCacheState)
	return err == nil && fi.IsDir()
}

// dnsCacheOn says whether users' DNS can go to the cache.
func dnsCacheOn() bool {
	if !dnsCacheStateOn() {
		return false
	}
	for i := 0; i < dnsCacheTries; i++ {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		if dnsCacheProbe() {
			return true
		}
	}
	logger.Warning("the DNS cache at", dnsCacheAddr, "does not answer, so users' DNS does not go to it")
	return false
}

// probeDNSCache asks the cache for localhost's address, which it answers
// itself. Any answer will do, an error too: something answers DNS there.
func probeDNSCache() bool { return probeDNS(dnsCacheAddr) }

func probeDNS(addr string) bool {
	c, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	q := []byte{0x78, 0x75, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 0, 1, 0, 1}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(q); err != nil {
		return false
	}
	b := make([]byte, 512)
	n, err := c.Read(b)
	return err == nil && n >= 12 && b[0] == q[0] && b[1] == q[1] && b[2]&0x80 != 0
}

// withDNSCache sends port 53 to the cache when it is on: an outbound that
// sends everything to dnsCacheAddr (freedom with a fixed redirect, which
// carries no direct mark: see withDirectMark) and a rule for it ahead of the
// template's own, after the panel's API rule. Ones already there (a
// template copied from a running config) are taken out first, so they are
// there only while the cache is on.
func withDNSCache(cfg *xray.Config) {
	var obs []json.RawMessage
	if json.Unmarshal(cfg.OutboundConfigs, &obs) != nil {
		return
	}
	var routing map[string]json.RawMessage
	if len(bytes.TrimSpace(cfg.RouterConfig)) > 0 && json.Unmarshal(cfg.RouterConfig, &routing) != nil {
		return
	}
	if routing == nil {
		routing = map[string]json.RawMessage{}
	}
	var rules []json.RawMessage
	if r, ok := routing["rules"]; ok && json.Unmarshal(r, &rules) != nil {
		return
	}

	changed := false
	keptObs := obs[:0:0]
	for _, ob := range obs {
		if tagOf(ob, "tag") == dnsCacheTag {
			changed = true
			continue
		}
		keptObs = append(keptObs, ob)
	}
	keptRules := rules[:0:0]
	for _, r := range rules {
		if tagOf(r, "ruleTag") == dnsCacheTag {
			changed = true
			continue
		}
		keptRules = append(keptRules, r)
	}
	// The first outbound is the default one: one of the template's.
	if len(keptObs) > 0 && dnsCacheOn() {
		at := 0
		for at < len(keptRules) && apiRule(keptRules[at]) {
			at++
		}
		rule := json.RawMessage(`{"type":"field","ruleTag":"` + dnsCacheTag + `","port":"53","outboundTag":"` + dnsCacheTag + `"}`)
		keptRules = append(keptRules[:at], append([]json.RawMessage{rule}, keptRules[at:]...)...)
		keptObs = append(keptObs, json.RawMessage(`{"tag":"`+dnsCacheTag+`","protocol":"freedom","settings":{"redirect":"`+dnsCacheAddr+`"}}`))
		changed = true
	}
	if !changed {
		return
	}
	rb, err1 := json.Marshal(keptRules)
	routing["rules"] = rb
	newRouting, err2 := json.Marshal(routing)
	newObs, err3 := json.Marshal(keptObs)
	if err1 != nil || err2 != nil || err3 != nil {
		return
	}
	cfg.RouterConfig = json_util.RawMessage(newRouting)
	cfg.OutboundConfigs = json_util.RawMessage(newObs)
}

// tagOf prints an object's string field ("" when it has none).
func tagOf(raw json.RawMessage, field string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(m[field], &s) != nil {
		return ""
	}
	return s
}

// hasOutboundTag says whether an outbound has this tag.
func hasOutboundTag(raw json_util.RawMessage, tag string) bool {
	var obs []json.RawMessage
	if json.Unmarshal(raw, &obs) != nil {
		return false
	}
	for _, ob := range obs {
		if tagOf(ob, "tag") == tag {
			return true
		}
	}
	return false
}

// apiRule says whether a routing rule is the one for the panel's API
// (inboundTag "api"), which stays first.
func apiRule(raw json.RawMessage) bool {
	var r struct {
		InboundTag any `json:"inboundTag"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return false
	}
	switch t := r.InboundTag.(type) {
	case string:
		return t == "api"
	case []any:
		for _, v := range t {
			if s, _ := v.(string); s == "api" {
				return true
			}
		}
	}
	return false
}

var (
	dnsCacheMu       sync.Mutex
	dnsCacheMismatch int
)

// dnsCacheChecks is how many checks in a row (CheckDNSCache runs every 30
// s) the running core and the cache must disagree before the core is
// started again: a reload of the cache takes under a second.
const dnsCacheChecks = 3

// CheckDNSCache has the core started again when the cache stopped
// answering while users' DNS goes to it, or answers again while it does not.
func (s *XrayService) CheckDNSCache() {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if !s.IsXrayRunning() {
		dnsCacheMismatch = 0
		return
	}
	cfg := p.GetConfig()
	running := cfg != nil && hasOutboundTag(cfg.OutboundConfigs, dnsCacheTag)
	want := dnsCacheStateOn() && dnsCacheProbe()
	if running == want {
		dnsCacheMismatch = 0
		return
	}
	dnsCacheMismatch++
	if dnsCacheMismatch < dnsCacheChecks {
		return
	}
	dnsCacheMismatch = 0
	if want {
		logger.Info("the DNS cache answers: Xray restarts so that users' DNS goes to it")
	} else {
		logger.Warning("the DNS cache does not answer: Xray restarts so that users' DNS no longer goes to it")
	}
	s.SetToNeedRestart()
}
