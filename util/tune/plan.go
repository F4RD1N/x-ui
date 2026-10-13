package tune

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// KeyPlan is what x-ui will do about one sysctl key.
type KeyPlan struct {
	T          Target `json:"-"`
	Key        string `json:"key"`
	Live       string `json:"live"`
	Target     string `json:"target"`
	Others     string `json:"others,omitempty"`
	OthersFile string `json:"others_file,omitempty"`
	Want       string `json:"write,omitempty"`   // new live value; "" leaves it
	Persist    string `json:"persist,omitempty"` // value for 99-x-ui.conf; "" none
	State      string `json:"state"`             // ok, change, kept, read-only, missing, failed
	Note       string `json:"note,omitempty"`
}

// Plan is the whole of what an apply would do.
type Plan struct {
	Facts *Facts     `json:"facts"`
	Svc   Service    `json:"service"`
	Keys  []*KeyPlan `json:"sysctl"`

	Unit         *unitView `json:"-"`
	DropIn       string    `json:"-"` // "" when not a systemd host
	DropInNoFile int64     `json:"dropin_nofile,omitempty"`
	GoMemFrom    string    `json:"gomemlimit_set_in,omitempty"`
	GoGCFrom     string    `json:"gogc_set_in,omitempty"`
	ConfD        string    `json:"-"`
	ModulesLoad  string    `json:"-"`
	Modprobe     string    `json:"-"`

	Hash *KeyPlan `json:"ct_hashsize,omitempty"`

	baseNoFile  int64
	gomem, gogc string // what x-ui's drop-in sets ("" when set elsewhere)
}

// renderService renders the drop-in (systemd) or conf.d file (OpenRC).
func (p *Plan) renderService(bin string) {
	switch p.Facts.Init {
	case "systemd":
		p.DropIn = renderDropIn(p.DropInNoFile, p.gomem, p.gogc, bin)
	case "openrc":
		p.ConfD = renderOpenRC(p.DropInNoFile, p.gomem, p.gogc)
	}
}

// capNoFile keeps the service's open-file limit within fs.nr_open as it
// really is: systemd refuses to start a service whose limit is above it.
func (p *Plan) capNoFile(nrOpen int64, bin string) {
	if nrOpen <= 0 || p.DropInNoFile <= nrOpen {
		return
	}
	p.DropInNoFile = nrOpen
	if nrOpen <= p.baseNoFile {
		p.DropInNoFile = 0
	}
	p.renderService(bin)
}

func sysctlPath(key string) string { return "/proc/sys/" + strings.ReplaceAll(key, ".", "/") }

const hashsizePath = "/sys/module/nf_conntrack/parameters/hashsize"

func (e *Env) roNote(f *Facts) string {
	if e.OnlyNet {
		return "read-only (XUI_TUNE_ONLY=net)"
	}
	if f.Virt != "" {
		return "read-only (" + f.Virt + ")"
	}
	return "read-only"
}

// errState turns a failed write into a key state and note.
func errState(err error, f *Facts) (string, string) {
	var en syscall.Errno
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing", "missing"
	case errors.As(err, &en) && (en == syscall.EROFS || en == syscall.EACCES):
		v := ""
		if f.Virt != "" {
			v = " (" + f.Virt + ")"
		}
		return "read-only", "read-only" + v
	case errors.As(err, &en) && en == syscall.EPERM:
		if f.Container() {
			return "read-only", "not permitted here: enable it on the host"
		}
		return "read-only", "not permitted"
	case errors.As(err, &en) && en == syscall.EINVAL:
		return "failed", "the kernel rejected the value"
	case errors.As(err, &en) && en == syscall.ENOENT:
		return "missing", "missing (kernel module not available)"
	}
	return "failed", err.Error()
}

func i64(s string) int64 { return atoi64(s) }

// plan works out every action. It reads but never writes.
func (e *Env) plan(f *Facts, st *State) *Plan {
	p := &Plan{Facts: f, Svc: ServiceTargets(f)}
	others := e.othersSettings()
	for _, t := range Targets(f) {
		p.Keys = append(p.Keys, e.planKey(t, f, st, others))
	}

	// The service.
	p.Unit = e.readUnit()
	p.gomem, p.gogc = p.Svc.GoMemLimit, p.Svc.GoGC
	switch f.Init {
	case "systemd":
		if from := e.envSetElsewhere(p.Unit, "GOMEMLIMIT"); from != "" {
			p.GoMemFrom, p.gomem = from, ""
		}
		if from := e.envSetElsewhere(p.Unit, "GOGC"); from != "" {
			p.GoGCFrom, p.gogc = from, ""
		}
		p.baseNoFile = p.Unit.baseNoFile()
	case "openrc":
		conf := e.readTrim("/etc/conf.d/x-ui")
		if strings.Contains(conf, "GOMEMLIMIT=") {
			p.GoMemFrom, p.gomem = "/etc/conf.d/x-ui", ""
		}
		if strings.Contains(conf, "GOGC=") {
			p.GoGCFrom, p.gogc = "/etc/conf.d/x-ui", ""
		}
		p.baseNoFile = BaseNoFile // x-ui.rc's rc_ulimit
	}
	if p.Svc.NoFile > p.baseNoFile {
		p.DropInNoFile = p.Svc.NoFile
	}
	p.renderService(e.Bin)
	for _, k := range p.Keys {
		if k.Key == "fs.nr_open" && k.Want == "" && k.Live != "" {
			p.capNoFile(i64(k.Live), e.Bin) // not being raised: it is the ceiling
		}
	}

	// Modules for BBR and fq, when x-ui sets BBR and they are modules.
	if !f.Container() {
		for _, k := range p.Keys {
			if k.Key != "net.ipv4.tcp_congestion_control" || k.State == "kept" || k.State == "read-only" || k.State == "missing" {
				continue
			}
			var mods []string
			if f.BBRModule {
				mods = append(mods, "tcp_bbr")
			}
			if f.FQModule {
				mods = append(mods, "sch_fq")
			}
			if len(mods) > 0 {
				p.ModulesLoad = Header + strings.Join(mods, "\n") + "\n"
			}
		}
	}

	// Conntrack hash size: raise-only, live and in modprobe.d.
	if p.Svc.Hashsize > 0 {
		h := &KeyPlan{Key: "nf_conntrack hashsize", Target: fmt.Sprint(p.Svc.Hashsize)}
		want := p.Svc.Hashsize
		otherN, otherF := e.modprobeHashsize()
		h.Others, h.OthersFile = fmt.Sprint(otherN), otherF
		live, err := e.read(hashsizePath)
		switch {
		case err != nil:
			h.State, h.Note = "missing", "nf_conntrack not loaded"
		case e.writable(hashsizePath) != nil:
			h.Live = strings.TrimSpace(live)
			h.State, h.Note = "read-only", e.roNote(f)
		default:
			h.Live = strings.TrimSpace(live)
			if i64(h.Live) < want {
				h.Want = fmt.Sprint(want)
				h.State, h.Note = "change", "raise from "+h.Live
			} else {
				h.State, h.Note = "ok", ""
			}
		}
		if want > otherN && !f.Container() && !e.OnlyNet {
			h.Persist = fmt.Sprint(want)
			p.Modprobe = Header + "options nf_conntrack hashsize=" + h.Persist + "\n"
		} else if otherN >= want && h.State == "ok" {
			h.Note = "kept: " + otherF
		}
		p.Hash = h
	}
	return p
}

func (e *Env) planKey(t Target, f *Facts, st *State, others map[string]Setting) *KeyPlan {
	k := &KeyPlan{T: t, Key: t.Key, Target: t.Text()}
	path := sysctlPath(t.Key)
	ks := st.Keys[t.Key]

	raw, err := e.read(path)
	if err != nil {
		k.State, k.Note = "missing", "missing"
		if ks != nil && ks.File != "" {
			// Keep the line written earlier (the module is loaded later).
			k.Persist = ks.File
		}
		return k
	}
	k.Live = normValue(raw)
	if o, ok := others[t.Key]; ok {
		k.Others, k.OthersFile = o.Value, o.File
	} else if ks != nil && ks.Orig != "" {
		k.Others = ks.Orig
	} else {
		k.Others = k.Live
	}
	if err := e.writable(path); err != nil {
		k.State, k.Note = errState(err, f)
		if k.State == "read-only" && e.OnlyNet {
			k.Note = e.roNote(f)
		}
		return k
	}
	// Someone else changed the live value since x-ui wrote it.
	foreign := ks == nil || ks.Written == "" || ks.Written != k.Live

	switch t.Class {
	case ClassLimit:
		lv, ov := i64(k.Live), i64(k.Others)
		want := max(t.Num, ov)
		if foreign {
			want = max(want, lv)
		}
		if t.Num > ov {
			k.Persist = fmt.Sprint(t.Num)
		}
		if lv < want {
			k.Want = fmt.Sprint(want)
		}
		k.State = "ok"
		switch {
		case k.Want != "":
			k.State, k.Note = "change", "raise from "+k.Live
		case ov > t.Num && k.OthersFile != "":
			k.State, k.Note = "kept", "set higher by "+k.OthersFile
		case lv > t.Num:
			k.State, k.Note = "kept", "already higher"
		}

	case ClassField:
		lf, of := strings.Fields(k.Live), strings.Fields(k.Others)
		if len(lf) != 3 {
			k.State, k.Note = "failed", "unexpected value"
			return k
		}
		if len(of) != 3 {
			of = lf
		}
		lv, ov := i64(lf[2]), i64(of[2])
		want := max(t.Num, ov)
		if foreign {
			want = max(want, lv)
		}
		if t.Num > ov {
			k.Persist = fmt.Sprintf("%s %s %d", of[0], of[1], t.Num)
		}
		if lv < want {
			k.Want = fmt.Sprintf("%s %s %d", lf[0], lf[1], want)
		}
		k.State = "ok"
		switch {
		case k.Want != "":
			k.State, k.Note = "change", "raise max from "+lf[2]
		case ov > t.Num && k.OthersFile != "":
			k.State, k.Note = "kept", "set higher by "+k.OthersFile
		case lv > t.Num:
			k.State, k.Note = "kept", "already higher"
		}

	case ClassWiden:
		lf, of := strings.Fields(k.Live), strings.Fields(k.Others)
		if len(lf) != 2 {
			k.State, k.Note = "failed", "unexpected value"
			return k
		}
		if len(of) != 2 {
			of = lf
		}
		llo, lhi, olo, ohi := i64(lf[0]), i64(lf[1]), i64(of[0]), i64(of[1])
		plo, phi := min(olo, t.Lo), max(ohi, t.Hi)
		if plo != olo || phi != ohi {
			k.Persist = fmt.Sprintf("%d %d", plo, phi)
		}
		nlo, nhi := min(llo, t.Lo), max(lhi, t.Hi)
		if nlo != llo || nhi != lhi {
			k.Want = fmt.Sprintf("%d %d", nlo, nhi)
			k.State, k.Note = "change", "widen from "+k.Live
		} else if llo < t.Lo {
			k.State, k.Note = "kept", "already wider"
		} else {
			k.State = "ok"
		}

	case ClassBits:
		lv, ov := i64(k.Live), i64(k.Others)
		if ov|t.Num != ov {
			k.Persist = fmt.Sprint(ov | t.Num)
		}
		if lv|t.Num != lv {
			k.Want = fmt.Sprint(lv | t.Num)
			k.State, k.Note = "change", "from "+k.Live
		} else {
			k.State = "ok"
		}

	case ClassChoice:
		if k.OthersFile != "" && e.adminOwned(k.OthersFile) {
			k.State, k.Note = "kept", "admin choice in "+k.OthersFile
			if k.Live != k.Others {
				k.Note += " (" + k.Others + ")"
			}
			return k
		}
		tv := t.Text()
		if t.OnlyFromZero {
			if k.Others == "0" {
				k.Persist = tv
			}
			if k.Live == "0" {
				k.Want = tv
				k.State, k.Note = "change", "from 0"
			} else if k.Live != tv {
				k.State, k.Note = "kept", "already "+k.Live
			} else {
				k.State = "ok"
			}
			return k
		}
		if k.Others != tv {
			k.Persist = tv
		}
		if k.Live != tv {
			k.Want = tv
			k.State, k.Note = "change", "from "+k.Live
		} else {
			k.State = "ok"
		}
	}
	return k
}

// renderSysctl writes 99-x-ui.conf from the plan; "" means no file.
func renderSysctl(keys []*KeyPlan) string {
	var b strings.Builder
	n := 0
	for _, k := range keys {
		if k.Persist == "" {
			continue
		}
		if n == 0 {
			b.WriteString(Header)
		}
		n++
		dash := ""
		if k.T.Optional {
			dash = "-"
		}
		fmt.Fprintf(&b, "\n# %s\n%s%s = %s\n", k.T.Why, dash, k.Key, k.Persist)
	}
	return b.String()
}
