//go:build linux

package tune

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// A local DNS cache. Xray resolves every domain a user asks for, and REALITY
// looks up its target on every connection, through /etc/resolv.conf. On a busy
// server that is 10,000 lookups a second. systemd-resolved answers them on one
// thread: at 80-90% of a core its socket dropped hundreds of queries a second,
// and each dropped query is a 5 s wait for a user's connection (a third of
// new connections stalled). A server that asks 1.1.1.1 directly pays a round
// trip on each. unbound, multi-threaded and caching, answers them in well
// under a millisecond with no drops; it forwards to the resolvers the server
// used before. /etc/resolv.conf names it first and the old resolver second.
//
// A host service: done by a fresh install and by "apply", never by an update.
// It leaves a server alone that already runs a DNS server of its own on
// 127.0.0.1, or whose resolv.conf another manager writes (NetworkManager,
// resolvconf), and never installs unbound again after an admin removed it.

const (
	ResolvConf       = "/etc/resolv.conf"
	resolvedStub     = "/run/systemd/resolve/stub-resolv.conf"
	resolvedUpstream = "/run/systemd/resolve/resolv.conf"
	UnboundDropIn    = "/etc/systemd/system/unbound.service.d/90-x-ui.conf"
	unboundMain      = "/etc/unbound/unbound.conf"
	unboundConfName  = "x-ui.conf"
)

// unboundConfDirs are where distributions include unbound's extra files from;
// revert also looks in them when the state is lost.
var unboundConfDirs = []string{"/etc/unbound/unbound.conf.d", "/etc/unbound/conf.d"}

// DNSState is what x-ui did to the DNS setup.
type DNSState struct {
	Was       string   `json:"was"` // "link:<target>" or "file:<backup>": /etc/resolv.conf before
	Upstreams []string `json:"upstreams"`
	Fallback  string   `json:"fallback"`
	Conf      string   `json:"conf"` // unbound's config file x-ui wrote
}

// dnsPlan is what the DNS part of an apply does.
type dnsPlan struct {
	Mode      string // resolved, static, ours; "" leaves DNS alone
	Note      string
	Upstreams []string
	Fallback  string
	Link      string // resolv.conf's link target, "" when it is a file
	Install   bool   // unbound is not installed yet
}

func isLoopback(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && a.IsLoopback()
}

// nameservers lists a resolv.conf's servers (zone ids dropped).
func nameservers(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			s, _, _ := strings.Cut(f[1], "%")
			if net.ParseIP(s) != nil && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// port53Taken reports whether something listens on 127.0.0.1:53 or *:53.
func (e *Env) port53Taken() bool {
	for _, file := range []string{"/proc/net/udp", "/proc/net/tcp"} {
		for _, l := range strings.Split(e.readTrim(file), "\n") {
			f := strings.Fields(l)
			if len(f) > 2 && (f[1] == "0100007F:0035" || f[1] == "00000000:0035") {
				return true
			}
		}
	}
	return false
}

func (e *Env) planDNS(f *Facts, st *State) *dnsPlan {
	p := &dnsPlan{}
	switch {
	case f.Container() || e.OnlyNet:
		p.Note = "container: kept by the host"
		return p
	case f.Init != "systemd":
		p.Note = "not a systemd host: left as it is"
		return p
	}
	if st.DNS != nil && e.isOurs(ResolvConf) {
		p.Mode, p.Upstreams, p.Fallback = "ours", st.DNS.Upstreams, st.DNS.Fallback
		p.Note = fmt.Sprintf("unbound at 127.0.0.1 (x-ui), forwarding to %s; then %s", strings.Join(p.Upstreams, ", "), p.Fallback)
		return p
	}
	if st.DNS != nil {
		p.Note = "kept: /etc/resolv.conf changed since x-ui wrote it"
		return p
	}
	text := e.readTrim(ResolvConf)
	if fi, err := os.Lstat(e.P(ResolvConf)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		p.Link, _ = os.Readlink(e.P(ResolvConf))
	}
	target := e.resolve(ResolvConf)
	servers := nameservers(text)
	switch {
	case p.Link != "" && target != resolvedStub && target != resolvedUpstream:
		p.Note = "kept: /etc/resolv.conf is managed elsewhere (" + target + ")"
		return p
	case p.Link == "" && (strings.Contains(text, "NetworkManager") || strings.Contains(text, "resolvconf")):
		p.Note = "kept: /etc/resolv.conf is written by NetworkManager or resolvconf"
		return p
	case target == resolvedStub || (p.Link == "" && len(servers) == 1 && servers[0] == "127.0.0.53"):
		p.Mode, p.Fallback = "resolved", "127.0.0.53"
		for _, s := range nameservers(e.readTrim(resolvedUpstream)) {
			if !isLoopback(s) {
				p.Upstreams = append(p.Upstreams, s)
			}
		}
	default:
		for _, s := range servers {
			if isLoopback(s) {
				p.Note = "kept: a DNS server of its own already answers at " + s
				return p
			}
		}
		p.Mode, p.Upstreams = "static", servers
		if len(servers) > 0 {
			p.Fallback = servers[0]
		}
	}
	switch {
	case len(p.Upstreams) == 0:
		p.Mode, p.Note = "", "kept: no upstream DNS server is known"
	case e.port53Taken() && !slices.Contains(st.Installed, "unbound"):
		p.Mode, p.Note = "", "kept: a DNS server already listens on port 53"
	case !e.have("unbound") && len(e.pkgRemoved("unbound")) > 0:
		p.Mode, p.Note = "", "kept: unbound was removed from this server"
	default:
		p.Install = !e.have("unbound")
		p.Note = "would cache lookups with unbound at 127.0.0.1, forwarding to " + strings.Join(p.Upstreams, ", ")
	}
	return p
}

// renderUnbound is x-ui's unbound config, sized by the machine.
func renderUnbound(f *Facts, ups []string) string {
	threads := clamp(int64(f.CPUs)/8, 1, 8)
	slabs := pow2ceil(float64(threads))
	msg := clamp(f.MemBytes/1024/MiB, 4, 256)
	var b strings.Builder
	b.WriteString(Header)
	b.WriteString(`# A DNS cache for xray (see 'x-ui tune -h'): many threads, no dropped
# lookups, forwarding to the resolvers this server used before.
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
`)
	fmt.Fprintf(&b, "    num-threads: %d\n    so-reuseport: yes\n    so-rcvbuf: 8m\n    so-sndbuf: 8m\n", threads)
	for _, s := range []string{"msg", "rrset", "infra", "key"} {
		fmt.Fprintf(&b, "    %s-cache-slabs: %d\n", s, slabs)
	}
	fmt.Fprintf(&b, "    msg-cache-size: %dm\n    rrset-cache-size: %dm\n", msg, 2*msg)
	b.WriteString(`    outgoing-range: 4096
    num-queries-per-thread: 2048
    prefetch: yes
    serve-expired: yes
    serve-expired-ttl: 3600
    serve-expired-client-timeout: 1500
    # No DNSSEC validation, as systemd-resolved does by default.
    module-config: "iterator"
    edns-buffer-size: 1232
    hide-identity: yes
    hide-version: yes
forward-zone:
    name: "."
`)
	for _, u := range ups {
		fmt.Fprintf(&b, "    forward-addr: %s\n", u)
	}
	return b.String()
}

// unboundDropIn keeps unbound running and gives it the open files its
// sockets need.
const unboundDropIn = Header + `[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=2
`

// renderResolv is x-ui's /etc/resolv.conf: unbound first, the old resolver
// after it, and the old file's search and options lines.
func renderResolv(old, fallback string) string {
	var b strings.Builder
	b.WriteString("# Written by x-ui tune (github.com/F4RD1N/x-ui).\n")
	b.WriteString("# unbound (a local DNS cache) first; the resolver from before only when it does\n# not answer. 'x-ui tune revert' puts back the old file.\nnameserver 127.0.0.1\n")
	if fallback != "" && fallback != "127.0.0.1" {
		fmt.Fprintf(&b, "nameserver %s\n", fallback)
	}
	opts := []string{"timeout:2", "attempts:2"}
	var keep []string
	for _, l := range strings.Split(old, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "options":
			for _, o := range f[1:] {
				if !strings.HasPrefix(o, "timeout:") && !strings.HasPrefix(o, "attempts:") && !slices.Contains(opts, o) {
					opts = append(opts, o)
				}
			}
		case "search", "domain", "sortlist":
			keep = append(keep, strings.Join(f, " "))
		}
	}
	fmt.Fprintf(&b, "options %s\n", strings.Join(opts, " "))
	for _, l := range keep {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// unboundConfDir is the directory unbound.conf includes "*.conf" files from.
func (e *Env) unboundConfDir() string {
	for _, l := range strings.Split(e.readTrim(unboundMain), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		for _, k := range []string{"include-toplevel:", "include:"} {
			if v, ok := strings.CutPrefix(l, k); ok {
				v = strings.Trim(strings.TrimSpace(v), `"`)
				if path.Base(v) == "*.conf" {
					return path.Dir(v)
				}
			}
		}
	}
	return ""
}

// dnsAnswers asks 127.0.0.1:53 for a few well-known names; one answer is
// enough. A test replaces it; under a fake root it always answers.
func (e *Env) dnsAnswers() error {
	if e.DNSProbe != nil {
		return e.DNSProbe()
	}
	if e.fake() {
		return nil
	}
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", "127.0.0.1:53")
	}}
	var last error
	for i := 0; i < 10; i++ {
		for _, n := range []string{"www.google.com", "one.one.one.one", "dns.google"} {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := res.LookupHost(ctx, n)
			cancel()
			if err == nil {
				return nil
			}
			last = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

func (e *Env) applyDNS(f *Facts, st *State, r *Result) {
	p := e.planDNS(f, st)
	switch p.Mode {
	case "":
		return
	case "ours":
		// Already set up: keep the config current.
		c1, err1 := e.writeFile(st.DNS.Conf, []byte(renderUnbound(f, st.DNS.Upstreams)), 0o644)
		c2, err2 := e.writeFile(UnboundDropIn, []byte(unboundDropIn), 0o644)
		if err := errors.Join(err1, err2); err != nil {
			r.problem("dns: %v", err)
		} else if c1 || c2 {
			_, _ = e.run("systemctl", "daemon-reload")
			_, _ = e.run("systemctl", "restart", "unbound")
			r.change("dns: unbound's config updated")
		}
		return
	}
	if p.Install {
		if err := e.pkgInstall("unbound"); err != nil {
			r.problem("dns: installing unbound: %v", err)
			return
		}
		st.Installed = addOnce(st.Installed, "unbound")
	}
	dir := e.unboundConfDir()
	if dir == "" {
		r.problem("dns: %s includes no directory of *.conf files: unbound not set up", unboundMain)
		return
	}
	conf := path.Join(dir, unboundConfName)
	if e.exists(conf) && !e.isOurs(conf) {
		r.problem("dns: %s is not x-ui's: unbound not set up", conf)
		return
	}
	undo := func() {
		e.remove(conf)
		e.remove(UnboundDropIn)
		_, _ = e.run("systemctl", "daemon-reload")
	}
	if _, err := e.writeFile(conf, []byte(renderUnbound(f, p.Upstreams)), 0o644); err != nil {
		r.problem("dns: %v", err)
		return
	}
	if _, err := e.writeFile(UnboundDropIn, []byte(unboundDropIn), 0o644); err != nil {
		r.problem("dns: %v", err)
		undo()
		return
	}
	_, _ = e.run("systemctl", "daemon-reload")
	if out, err := e.run("unbound-checkconf"); err != nil {
		r.problem("dns: unbound-checkconf refused the config: %v %s", err, out)
		undo()
		return
	}
	if _, err := e.run("systemctl", "is-enabled", "--quiet", "unbound"); err != nil {
		if _, err := e.run("systemctl", "enable", "unbound"); err == nil {
			st.Enabled = addOnce(st.Enabled, "unbound")
		}
	}
	if out, err := e.run("systemctl", "restart", "unbound"); err != nil {
		r.problem("dns: unbound did not start (%v %s); /etc/resolv.conf left as it was", err, out)
		return
	}
	if err := e.dnsAnswers(); err != nil {
		r.problem("dns: unbound does not answer (%v); /etc/resolv.conf left as it was", err)
		return
	}

	// Only now point the system at it. The new file replaces the link or the
	// old file in one rename: there is no moment without a resolv.conf.
	old, _ := e.read(ResolvConf)
	was := "link:" + p.Link
	if p.Link == "" {
		backup := BackupDir + ResolvConf
		mode := os.FileMode(0o644)
		if fi, err := os.Stat(e.P(ResolvConf)); err == nil {
			mode = fi.Mode().Perm()
		}
		if _, err := e.writeFile(backup, []byte(old), mode); err != nil {
			r.problem("dns: keeping a copy of %s: %v", ResolvConf, err)
			return
		}
		was = "file:" + backup
	}
	if _, err := e.writeFile(ResolvConf, []byte(renderResolv(old, p.Fallback)), 0o644); err != nil {
		r.problem("dns: writing %s: %v (left as it was)", ResolvConf, err)
		return
	}
	st.DNS = &DNSState{Was: was, Upstreams: p.Upstreams, Fallback: p.Fallback, Conf: conf}
	r.change("dns: unbound caches lookups at 127.0.0.1 (forwarding to %s); %s names it first, %s after",
		strings.Join(p.Upstreams, ", "), ResolvConf, p.Fallback)
}

// restoreResolv puts /etc/resolv.conf back as it was.
func (e *Env) restoreResolv(was string, r *Result) bool {
	if target, ok := strings.CutPrefix(was, "link:"); ok {
		// A new link renamed over the file: never a moment without one.
		tmp := e.P(ResolvConf + ".x-ui-restore")
		_ = os.Remove(tmp)
		if err := os.Symlink(target, tmp); err != nil {
			r.problem("restore %s: %v", ResolvConf, err)
			return false
		}
		if err := os.Rename(tmp, e.P(ResolvConf)); err != nil {
			os.Remove(tmp)
			r.problem("restore %s: %v", ResolvConf, err)
			return false
		}
		return true
	}
	if backup, ok := strings.CutPrefix(was, "file:"); ok {
		if err := e.move(backup, ResolvConf); err != nil {
			r.problem("restore %s: %v", ResolvConf, err)
			return false
		}
		return true
	}
	return false
}

func (e *Env) revertDNS(st *State, r *Result) {
	switch {
	case st.DNS != nil && e.isOurs(ResolvConf):
		if e.restoreResolv(st.DNS.Was, r) {
			r.change("restored %s", ResolvConf)
		}
	case st.DNS != nil:
		r.problem("%s changed since x-ui wrote it: left as it is", ResolvConf)
	case e.isOurs(ResolvConf) && e.exists(resolvedStub):
		// No state: systemd-resolved's stub is the usual original.
		if e.restoreResolv("link:"+resolvedStub, r) {
			r.change("pointed %s back at systemd-resolved (no state file)", ResolvConf)
		}
	}
	confs := []string{}
	if st.DNS != nil && st.DNS.Conf != "" {
		confs = append(confs, st.DNS.Conf)
	}
	for _, d := range unboundConfDirs {
		confs = addOnce(confs, path.Join(d, unboundConfName))
	}
	changed := false
	for _, c := range append(confs, UnboundDropIn) {
		if e.ownFile(c, "", r) {
			changed = true
		}
	}
	if changed {
		_, _ = e.run("systemctl", "daemon-reload")
		if !slices.Contains(st.Enabled, "unbound") {
			// unbound was the admin's before: it goes on with its own config.
			_, _ = e.run("systemctl", "try-restart", "unbound")
		}
	}
}

// dnsInfo is the DNS part of "x-ui tune status".
func (e *Env) dnsInfo(f *Facts, st *State) string {
	p := e.planDNS(f, st)
	if p.Mode == "ours" && f.Init == "systemd" && !e.fake() && !e.unitActive("unbound") {
		return p.Note + " (unbound is NOT running: the old resolver answers)"
	}
	return p.Note
}
