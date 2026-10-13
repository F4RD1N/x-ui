//go:build linux

package tune

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// unitLine is one "Key=Value" of a unit file's [Service] section.
type unitLine struct{ Key, Value, File string }

func parseUnit(data, file string) []unitLine {
	var out []unitLine
	section := ""
	for _, l := range strings.Split(data, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "[") {
			section = strings.Trim(l, "[]")
			continue
		}
		if section != "Service" {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			out = append(out, unitLine{strings.TrimSpace(k), strings.TrimSpace(v), file})
		}
	}
	return out
}

// unitView is the x-ui unit and its drop-ins, split around x-ui's own.
type unitView struct {
	Unit   string     // path of x-ui.service, "" when not installed
	Before []unitLine // the unit, then drop-ins sorting before x-ui's
	After  []unitLine // drop-ins sorting after x-ui's
	Later  []string   // those later drop-in files
	Legacy []string   // drop-ins an older x-ui tune.sh wrote
}

func (e *Env) readUnit() *unitView { return e.readUnitNamed("x-ui.service", DropInFile) }

// readUnitNamed reads a unit and its drop-ins, split around x-ui's own
// drop-in ours (which is left out).
func (e *Env) readUnitNamed(name, ours string) *unitView {
	v := &unitView{}
	for _, d := range unitDirs {
		if f := d + "/" + name; e.exists(f) {
			v.Unit = f
			break
		}
	}
	if v.Unit != "" {
		data, _ := e.read(e.resolve(v.Unit))
		v.Before = parseUnit(data, v.Unit)
	}
	byName := map[string]string{}
	for _, d := range unitDirs {
		for _, f := range e.glob(d + "/" + name + ".d/*.conf") {
			if _, ok := byName[path.Base(f)]; !ok {
				byName[path.Base(f)] = f
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	ourName := path.Base(ours)
	for _, n := range names {
		f := byName[n]
		if f == ours {
			continue
		}
		data, _ := e.read(e.resolve(f))
		if name == "x-ui.service" && strings.HasPrefix(data, legacyDropInMark) {
			v.Legacy = append(v.Legacy, f)
			continue
		}
		lines := parseUnit(data, f)
		if n < ourName {
			v.Before = append(v.Before, lines...)
		} else {
			v.After = append(v.After, lines...)
			v.Later = append(v.Later, f)
		}
	}
	return v
}

// execStart is the unit's command line as its files leave it: the last
// ExecStart= after the last empty one (which clears the list).
func (v *unitView) execStart() string {
	cmd := ""
	for _, l := range append(append([]unitLine{}, v.Before...), v.After...) {
		if l.Key == "ExecStart" {
			cmd = l.Value
		}
	}
	return cmd
}

// parseNoFile reads "N", "soft:hard" or "infinity" and returns the hard limit.
func parseNoFile(s string) int64 {
	s = strings.TrimSpace(s)
	if _, h, ok := strings.Cut(s, ":"); ok {
		s = h
	}
	if s == "infinity" {
		return math.MaxInt64
	}
	return atoi64(s)
}

// baseNoFile is the LimitNOFILE the unit and the drop-ins before x-ui's set.
func (v *unitView) baseNoFile() int64 {
	var n int64
	for _, l := range v.Before {
		if l.Key == "LimitNOFILE" {
			n = parseNoFile(l.Value)
		}
	}
	return n
}

var envFileRe = regexp.MustCompile(`^-?(.*)$`)

// envSetElsewhere says where a variable is set other than in x-ui's drop-in:
// an Environment= line, or an EnvironmentFile= (which overrides Environment=).
func (e *Env) envSetElsewhere(v *unitView, name string) string {
	re := regexp.MustCompile(`(^|[\s"'])` + name + `=`)
	all := append(append([]unitLine{}, v.Before...), v.After...)
	for _, l := range all {
		switch l.Key {
		case "Environment":
			if re.MatchString(l.Value) {
				return l.File
			}
		case "EnvironmentFile":
			f := envFileRe.FindStringSubmatch(l.Value)[1]
			if f == "" || !strings.HasPrefix(f, "/") {
				continue
			}
			data, err := e.read(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(data, "\n") {
				line = strings.TrimPrefix(strings.TrimSpace(line), "export ")
				if strings.HasPrefix(line, name+"=") {
					return f
				}
			}
		}
	}
	return ""
}

// overrides lists the settings of later drop-ins that win over x-ui's.
func (v *unitView) overrides() []string {
	var out []string
	for _, l := range v.After {
		switch l.Key {
		case "LimitNOFILE", "TasksMax", "KillMode", "TimeoutStopSec", "OOMScoreAdjust", "Restart", "LimitNPROC":
			out = append(out, fmt.Sprintf("%s=%s (%s)", l.Key, l.Value, l.File))
		case "Environment":
			for _, n := range []string{"GOMEMLIMIT", "GOGC"} {
				if strings.Contains(l.Value, n+"=") {
					out = append(out, fmt.Sprintf("%s (%s)", strings.Trim(l.Value, `"`), l.File))
				}
			}
		}
	}
	return out
}

// renderDropIn writes x-ui's drop-in for the service.
func renderDropIn(noFile int64, gomem, gogc, bin string) string {
	var b strings.Builder
	b.WriteString(Header)
	b.WriteString("[Service]\n")
	if noFile > 0 {
		fmt.Fprintf(&b, "LimitNOFILE=%d\n", noFile)
	}
	if gomem != "" {
		fmt.Fprintf(&b, "Environment=GOMEMLIMIT=%s\n", gomem)
	}
	if gogc != "" {
		fmt.Fprintf(&b, "Environment=GOGC=%s\n", gogc)
	}
	fmt.Fprintf(&b, "ExecStartPre=-%s tune apply --boot\n", bin)
	return b.String()
}

// renderOpenRC writes the file x-ui.rc's start_pre sources.
func renderOpenRC(noFile int64, gomem, gogc string) string {
	var b strings.Builder
	b.WriteString(Header)
	if noFile > 0 {
		fmt.Fprintf(&b, "ulimit -n %d\n", noFile)
	}
	if gomem != "" {
		fmt.Fprintf(&b, "export GOMEMLIMIT=%s\n", gomem)
	}
	if gogc != "" {
		fmt.Fprintf(&b, "export GOGC=%s\n", gogc)
	}
	return b.String()
}

// swapUnitName is systemd-escape -p --suffix=swap of the swapfile path.
func swapUnitName(p string) string {
	p = strings.Trim(p, "/")
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.' && i > 0, c == ':':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String() + ".swap"
}
