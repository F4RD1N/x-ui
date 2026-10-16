package service

// The direct mark.
//
// Freedom resolves an allowed name itself and dials whatever address comes
// back; routing never sees that address. So a name that points at 127.0.0.1
// -- there are many, and anyone can register more -- reaches what listens
// only on this server's loopback: the cores' API, which takes commands
// without a password, their metrics, the DNS cache. Every connection a
// freedom outbound makes therefore carries a socket mark, and "x-ui protect"
// (run by every install and update) refuses packets with that mark on their
// way to this server's loopback or to a private network (x-ui.sh,
// protect_mark).

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

// directMark is the mark; x-ui.sh's protect_mark must match it.
const directMark = 4242

var (
	canMarkOnce sync.Once
	canMark     bool
	// markProbe says whether this process may set a socket's mark. A core
	// that may not fails every connection of an outbound with a mark, so
	// none is given then.
	markProbe = probeSocketMark
)

func canMarkSockets() bool {
	canMarkOnce.Do(func() {
		var err error
		canMark, err = markProbe()
		if !canMark {
			logger.Warning("socket marks are not available here, so the cores' direct connections carry none:", err)
		}
	})
	return canMark
}

// withDirectMark gives every freedom outbound the direct mark. One that sets
// a mark of its own keeps it.
func withDirectMark(raw json_util.RawMessage) json_util.RawMessage {
	if len(raw) == 0 || !canMarkSockets() {
		return raw
	}
	var obs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&obs) != nil {
		return raw
	}
	changed := false
	for _, ob := range obs {
		if ob == nil {
			continue
		}
		// The core takes the protocol in any case, and "direct" for freedom.
		if p, _ := ob["protocol"].(string); !strings.EqualFold(p, "freedom") && !strings.EqualFold(p, "direct") {
			continue
		}
		ss, _ := ob["streamSettings"].(map[string]any)
		if ss == nil {
			ss = map[string]any{}
			ob["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
			ss["sockopt"] = so
		}
		if m, ok := so["mark"].(json.Number); ok && m.String() != "0" {
			continue
		}
		so["mark"] = directMark
		changed = true
	}
	if !changed {
		return raw
	}
	b, err := json.Marshal(obs)
	if err != nil {
		return raw
	}
	return b
}
