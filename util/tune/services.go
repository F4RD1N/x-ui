//go:build linux

package tune

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Host services: a time-sync client (VMess and Shadowsocks 2022 reject
// clients whose clock is off by more than 120 s / 30 s) and a small swapfile
// on tiny VMs; irqbalance's policy for the NICs is in irqbalance.go (x-ui no
// longer installs irqbalance; revert still undoes what older versions did).
// None of it applies in a container. They run on a fresh install and a
// manual apply, never on an update (see ApplyOptions.Host), and never undo an
// admin's choice: a client that is installed but off stays off, and a
// package the admin removed is not installed again.

var timeUnits = []string{"chronyd", "chrony", "ntpd", "ntp", "ntpsec", "openntpd", "systemd-timesyncd"}

func (e *Env) unitActive(u string) bool {
	_, err := e.run("systemctl", "is-active", "--quiet", u)
	return err == nil
}

func (e *Env) unitExists(u string) bool {
	out, err := e.run("systemctl", "list-unit-files", "--no-legend", u)
	return err == nil && strings.Contains(out, u)
}

// pkgInstall installs a package with whatever package manager there is.
func (e *Env) pkgInstall(pkg string) error {
	long := 5 * time.Minute
	switch {
	case e.have("apt-get"):
		if _, err := e.Run(long, "apt-get", "install", "-y", "-qq", pkg); err != nil {
			_, _ = e.Run(long, "apt-get", "update", "-qq")
			_, err = e.Run(long, "apt-get", "install", "-y", "-qq", pkg)
			return err
		}
		return nil
	case e.have("dnf"):
		_, err := e.Run(long, "dnf", "install", "-y", "-q", pkg)
		return err
	case e.have("yum"):
		_, err := e.Run(long, "yum", "install", "-y", "-q", pkg)
		return err
	case e.have("apk"):
		_, err := e.Run(long, "apk", "add", "--no-cache", pkg)
		return err
	case e.have("pacman"):
		_, err := e.Run(long, "pacman", "-S", "--noconfirm", "--needed", pkg)
		return err
	}
	return fmt.Errorf("no package manager found")
}

// pkgRemoved lists those of pkgs that dpkg remembers as removed ("apt
// remove" leaves them as "deinstall ok config-files"): an admin took them
// off this machine. Other package managers keep no such record.
func (e *Env) pkgRemoved(pkgs ...string) []string {
	if !e.have("dpkg-query") {
		return nil
	}
	// Missing packages make it exit 1; the others are still listed.
	out, _ := e.run("dpkg-query", append([]string{"-W", "--showformat=${Package} ${Status}\n"}, pkgs...)...)
	var gone []string
	for _, l := range strings.Split(out, "\n") {
		fs := strings.Fields(l)
		if len(fs) >= 2 && slices.Contains(pkgs, fs[0]) && (fs[1] == "deinstall" || fs[1] == "purge") {
			gone = append(gone, fs[0])
		}
	}
	return gone
}

func addOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

func (e *Env) services(f *Facts, st *State, r *Result) {
	if e.OnlyNet {
		return
	}
	e.timeSync(f, st, r)
	e.swap(f, st, r)
	e.applyCarrier(f, st, r)
	e.applyDNS(f, st, r)
}

func (e *Env) timeSync(f *Facts, st *State, r *Result) {
	if f.Container() || f.Init != "systemd" {
		return
	}
	for _, u := range timeUnits {
		if e.unitActive(u) {
			return
		}
	}
	if e.unitExists("systemd-timesyncd.service") {
		// Installed but not running: turned off ("timedatectl set-ntp
		// false"), or unable to start. That is the admin's to decide.
		if out, err := e.run("timedatectl", "show", "-p", "NTP", "--value"); err == nil && out == "no" {
			r.problem("time sync: systemd-timesyncd is turned off; 'timedatectl set-ntp true' turns it on")
		}
		return
	}
	if gone := e.pkgRemoved("chrony", "systemd-timesyncd", "ntp", "ntpsec", "openntpd"); len(gone) > 0 {
		r.problem("time sync: none runs, and %s was removed from this server: chrony not installed", strings.Join(gone, ", "))
		return
	}
	if err := e.pkgInstall("chrony"); err != nil {
		r.problem("time sync: installing chrony: %v", err)
		return
	}
	st.Installed = addOnce(st.Installed, "chrony")
	unit := "chronyd"
	if e.unitExists("chrony.service") {
		unit = "chrony"
	}
	if _, err := e.run("systemctl", "enable", "--now", unit); err != nil {
		r.problem("time sync: enabling %s: %v", unit, err)
		return
	}
	st.Enabled = addOnce(st.Enabled, unit)
	r.change("time sync: installed and enabled chrony")
}

const swapMark = "# x-ui tune swapfile"

// swapEligible says whether x-ui should create its swapfile, and why not.
func (e *Env) swapEligible(f *Facts, st *State) (bool, string) {
	switch {
	case f.MemBytes >= 1792*MiB:
		return false, ""
	case f.Container():
		return false, "container: skipped"
	case f.SwapActive:
		return false, "swap already active"
	case st.SwapGone:
		return false, "removed by the admin: not recreated"
	}
	dir := "/var/lib"
	var sfs unix.Statfs_t
	if err := unix.Statfs(e.P(dir), &sfs); err != nil {
		return false, "cannot check the filesystem"
	}
	switch uint32(sfs.Type) {
	case 0xEF53, 0x58465342: // ext2/3/4, xfs
	default:
		return false, "filesystem does not suit a swapfile"
	}
	if int64(sfs.Bavail)*int64(sfs.Bsize) < 3*GiB {
		return false, "less than 3 GiB free"
	}
	return true, ""
}

func (e *Env) swap(f *Facts, st *State, r *Result) {
	if st.Swap != "" {
		if !e.exists(SwapFile) {
			st.Swap, st.SwapGone = "", true
			r.change("swapfile: removed by the admin, not recreated")
		}
		return
	}
	ok, _ := e.swapEligible(f, st)
	if !ok || f.Init == "" {
		return
	}
	if err := e.makeSwapFile(); err != nil {
		r.problem("swapfile: %v", err)
		return
	}
	switch f.Init {
	case "systemd":
		unit := swapUnitName(SwapFile)
		content := Header + "[Unit]\nDescription=x-ui swapfile\n\n[Swap]\nWhat=" + SwapFile + "\n\n[Install]\nWantedBy=swap.target\n"
		if _, err := e.writeFile("/etc/systemd/system/"+unit, []byte(content), 0o644); err != nil {
			r.problem("swapfile: %v", err)
			e.remove(SwapFile)
			return
		}
		_, _ = e.run("systemctl", "daemon-reload")
		if _, err := e.run("systemctl", "enable", "--now", unit); err != nil && !e.fake() {
			r.problem("swapfile: enable %s: %v", unit, err)
		}
		st.Swap = "unit:" + unit
	case "openrc":
		fstab, _ := e.read("/etc/fstab")
		if !strings.Contains(fstab, swapMark) {
			if !strings.HasSuffix(fstab, "\n") && fstab != "" {
				fstab += "\n"
			}
			fstab += swapMark + "\n" + SwapFile + " none swap sw 0 0\n"
			if err := os.WriteFile(e.P("/etc/fstab"), []byte(fstab), 0o644); err != nil {
				r.problem("swapfile: fstab: %v", err)
				e.remove(SwapFile)
				return
			}
		}
		_, _ = e.run("swapon", SwapFile)
		st.Swap = "fstab"
	}
	r.change("swapfile: created 1 GiB at %s (less than 1.75 GiB of RAM)", SwapFile)
}

func (e *Env) makeSwapFile() error {
	p := e.P(SwapFile)
	if err := os.MkdirAll(e.P("/var/lib/x-ui"), 0o755); err != nil {
		return err
	}
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if e.fake() {
		return fh.Truncate(GiB) // sparse; never a real swapfile
	}
	if err := unix.Fallocate(int(fh.Fd()), 0, 0, GiB); err != nil {
		// No fallocate on this filesystem: write the zeros.
		buf := make([]byte, MiB)
		for i := int64(0); i < 1024; i++ {
			if _, werr := fh.Write(buf); werr != nil {
				os.Remove(p)
				return werr
			}
		}
	}
	if err := fh.Sync(); err != nil {
		os.Remove(p)
		return err
	}
	if out, err := e.run("mkswap", SwapFile); err != nil {
		os.Remove(p)
		return fmt.Errorf("mkswap: %v %s", err, out)
	}
	return nil
}

func (e *Env) revertServices(f *Facts, st *State, r *Result) {
	// resolv.conf goes back before unbound stops.
	e.revertDNS(st, r)
	e.revertCarrier(st, r)
	if st.Swap != "" && e.exists(SwapFile) {
		avail := meminfo(e.readTrim("/proc/meminfo"), "MemAvailable")
		used := swapUsed(e.readTrim("/proc/swaps"), SwapFile)
		if !e.fake() && used >= 0 && avail <= used+256*MiB {
			r.problem("swapfile kept: not enough free memory to turn it off (%d MiB in use)", used/MiB)
		} else {
			_, _ = e.run("swapoff", SwapFile)
			if unit, ok := strings.CutPrefix(st.Swap, "unit:"); ok {
				_, _ = e.run("systemctl", "disable", unit)
				e.remove("/etc/systemd/system/" + unit)
				_, _ = e.run("systemctl", "daemon-reload")
			} else {
				e.dropFstabSwap()
			}
			e.remove(SwapFile)
			r.change("swapfile: removed")
		}
	}
	if st.NTP {
		_, _ = e.run("timedatectl", "set-ntp", "false")
		r.change("time sync: turned systemd-timesyncd off again (VMess and Shadowsocks 2022 need an accurate clock)")
	}
	for _, u := range st.Enabled {
		_, _ = e.run("systemctl", "disable", "--now", u)
		r.change("disabled %s", u)
	}
	if len(st.Installed) > 0 {
		r.change("packages x-ui installed are left installed: %s", strings.Join(st.Installed, ", "))
	}
}

func (e *Env) dropFstabSwap() {
	fstab, err := e.read("/etc/fstab")
	if err != nil {
		return
	}
	var out []string
	skip := false
	for _, l := range strings.Split(fstab, "\n") {
		if l == swapMark {
			skip = true
			continue
		}
		if skip && strings.HasPrefix(l, SwapFile+" ") {
			skip = false
			continue
		}
		skip = false
		out = append(out, l)
	}
	_ = os.WriteFile(e.P("/etc/fstab"), []byte(strings.Join(out, "\n")), 0o644)
}

// swapUsed is how much of a swap device is in use, -1 when it is not active.
func swapUsed(swaps, file string) int64 {
	for _, l := range strings.Split(swaps, "\n") {
		fs := strings.Fields(l)
		if len(fs) >= 4 && fs[0] == file {
			return atoi64(fs[3]) * KiB
		}
	}
	return -1
}
