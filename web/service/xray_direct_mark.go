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
	"net"
	"strconv"
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
// a mark of its own keeps it. Where this process may not set marks, the
// direct mark is taken off instead: a template copied from a server that
// had it (the mark written into it by hand) would otherwise fail every
// direct connection here.
func withDirectMark(raw json_util.RawMessage) json_util.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	mark := canMarkSockets()
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
		so, _ := ss["sockopt"].(map[string]any)
		m, _ := so["mark"].(json.Number)
		// One that sends everything to a fixed address of the admin's
		// ("redirect": "127.0.0.1:53") dials no name it resolved: it is
		// left as it is, wherever that address is.
		if mark && fixedRedirect(ob) {
			continue
		}
		if !mark {
			if m.String() == strconv.Itoa(directMark) {
				delete(so, "mark")
				changed = true
			}
			continue
		}
		if m != "" && m.String() != "0" {
			continue
		}
		if ss == nil {
			ss = map[string]any{}
			ob["streamSettings"] = ss
		}
		if so == nil {
			so = map[string]any{}
			ss["sockopt"] = so
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

// fixedRedirect says whether a freedom outbound sends every connection to
// one address of its own: a redirect with a host other than 0.0.0.0 or ::
// (freedom ignores those and dials the original address, as it does for a
// redirect that only changes the port).
func fixedRedirect(ob map[string]any) bool {
	st, _ := ob["settings"].(map[string]any)
	r, _ := st["redirect"].(string)
	if r == "" {
		return false
	}
	host, _, err := net.SplitHostPort(r)
	if err != nil {
		host = r
	}
	host = strings.Trim(host, "[]")
	return host != "" && host != "0.0.0.0" && host != "::"
}
