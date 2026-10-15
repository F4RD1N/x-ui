//go:build linux

package tune

import (
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// Keeping the addresses through a link drop. systemd-networkd removes every
// address of an interface whose link goes down, and puts them back when it
// comes up. A per-core outgoing IP then vanishes for the seconds the link is
// down, and every connection sending from it breaks, where it could otherwise
// have waited the drop out (seen on a server whose cable flapped every few
// minutes). A drop-in for the uplink's .network file keeps the addresses
// (ConfigureWithoutCarrier, IgnoreCarrierLoss: netplan's "ignore-carrier").
// Only for uplinks systemd-networkd manages; a host setting, done by a fresh
// install and by "apply", never by an update.

// carrierDropIn is the drop-in's name inside <network file>.d/.
const carrierDropIn = "90-x-ui-keep-ips.conf"

const carrierConf = Header + `# Keep this interface's addresses while its link is down: x-ui's per-core
# outgoing IPs, and the connections sending from them, live through a link drop.
[Network]
ConfigureWithoutCarrier=yes
IgnoreCarrierLoss=yes
`

// carrierPlan is one uplink's state.
type carrierPlan struct {
	Dev     string
	Network string // its .network file ("" when networkd does not manage it)
	DropIn  string // x-ui's drop-in to write ("" none)
	Note    string
}

var carrierKept = regexp.MustCompile(`(?mi)^\s*(ConfigureWithoutCarrier\s*=\s*(yes|true|on|1)|IgnoreCarrierLoss\s*=\s*(yes|true|on|1|[0-9]))`)

// planCarrier looks at the devices the default routes leave through.
func (e *Env) planCarrier(f *Facts) []carrierPlan {
	if f.Container() || f.Init != "systemd" || e.OnlyNet {
		return nil
	}
	seen := map[string]bool{}
	var out []carrierPlan
	for _, rt := range hw.DefaultRoutes(e.hw()) {
		if seen[rt.Dev] {
			continue
		}
		seen[rt.Dev] = true
		c := carrierPlan{Dev: rt.Dev}
		idx := e.readTrim("/sys/class/net/" + rt.Dev + "/ifindex")
		for _, l := range strings.Split(e.readTrim("/run/systemd/netif/links/"+idx), "\n") {
			if v, ok := strings.CutPrefix(l, "NETWORK_FILE="); ok && idx != "" {
				c.Network = v
			}
		}
		switch {
		case c.Network == "":
			c.Note = "not managed by systemd-networkd"
		default:
			own := path.Join("/etc/systemd/network", path.Base(c.Network)+".d", carrierDropIn)
			if e.isOurs(own) {
				c.DropIn, c.Note = own, "addresses kept through link drops (x-ui)"
				break
			}
			// The file itself, then its drop-ins in every networkd directory.
			text := e.readTrim(c.Network)
			for _, d := range []string{"/etc/systemd/network", "/run/systemd/network", "/usr/local/lib/systemd/network", "/usr/lib/systemd/network", "/lib/systemd/network"} {
				for _, p := range e.glob(path.Join(d, path.Base(c.Network)+".d", "*.conf")) {
					text += "\n" + e.readTrim(p)
				}
			}
			if carrierKept.MatchString(text) {
				c.Note = "addresses already kept through link drops (" + path.Base(c.Network) + ")"
				break
			}
			c.DropIn, c.Note = own, "would keep the addresses through link drops"
		}
		out = append(out, c)
	}
	return out
}

func (e *Env) applyCarrier(f *Facts, st *State, r *Result) {
	wrote := false
	for _, c := range e.planCarrier(f) {
		if c.DropIn == "" {
			continue
		}
		changed, err := e.writeFile(c.DropIn, []byte(carrierConf), 0o644)
		if err != nil {
			r.problem("%s: keeping addresses through link drops: %v", c.Dev, err)
			continue
		}
		st.Carrier = addOnce(st.Carrier, c.DropIn)
		if changed {
			wrote = true
			r.change("%s: addresses kept through link drops (%s)", c.Dev, c.DropIn)
		}
	}
	if wrote {
		// Reconfigures the links whose .network changed; static addresses
		// stay where they are.
		if _, err := e.run("networkctl", "reload"); err != nil && !e.fake() {
			r.problem("networkctl reload: %v (the drop-in takes effect at the next boot)", err)
		}
	}
}

func (e *Env) revertCarrier(st *State, r *Result) {
	removed := false
	sort.Strings(st.Carrier)
	for _, p := range st.Carrier {
		if !e.isOurs(p) {
			continue
		}
		if ok, err := e.remove(p); err != nil {
			r.problem("remove %s: %v", p, err)
		} else if ok {
			removed = true
			r.change("removed %s", p)
			_ = removeEmptyDir(e, path.Dir(p))
		}
	}
	if removed {
		_, _ = e.run("networkctl", "reload")
	}
}

// carrierInfo is the link-drop part of "x-ui tune status".
func (e *Env) carrierInfo(f *Facts) []string {
	var out []string
	for _, c := range e.planCarrier(f) {
		out = append(out, "link drops ("+c.Dev+"): "+c.Note)
	}
	return out
}

// removeEmptyDir removes a directory x-ui emptied; one with other files stays.
func removeEmptyDir(e *Env, dir string) error { return os.Remove(e.P(dir)) }
