//go:build linux

// Package tune applies the server settings an x-ui box needs: kernel limits
// (sysctl), the service's open-file limit and Go memory settings, and a few
// host services. It is the "x-ui tune" command.
//
// It only raises limits: a value that an admin or another tool set higher is
// kept, x-ui writes only files of its own, and "x-ui tune revert" undoes
// exactly what it did. See docs in the usage text and in README.md.
//
// Test-only environment variables (deliberately not in the usage text):
//
//	XUI_TUNE_ROOT=<dir>   every path is taken below <dir>, and no external
//	                      command runs (each is recorded instead). A path that
//	                      would resolve outside <dir> panics.
//	XUI_TUNE_ONLY=net     only /proc/sys/net/* (and the queue files of the
//	                      XUI_TUNE_NIC devices) is written live, no
//	                      interrupt is moved, irqbalance is left alone, and no
//	                      external command runs; used for the network-namespace
//	                      test.
//	XUI_TUNE_NIC=<dev>[,<dev>]
//	                      these devices are the uplinks (with XUI_TUNE_ONLY=net
//	                      or XUI_TUNE_ROOT only); ethtool changes are allowed on
//	                      them alone.
//	XUI_TUNE_FACTS=<json> overrides detected facts (mem_bytes, cpus, kernel,
//	                      virt, init, page_size).
//	XUI_TUNE_BIN=<path>   the x-ui binary named in the unit's ExecStartPre.
package tune

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"golang.org/x/sys/unix"
)

// errNotRun is what a command returns when commands are faked.
var errNotRun = errors.New("command not run (test mode)")

// FactsOverride replaces detected facts (XUI_TUNE_FACTS).
type FactsOverride struct {
	MemBytes int64  `json:"mem_bytes,omitempty"`
	CPUs     int    `json:"cpus,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Virt     string `json:"virt,omitempty"`
	Init     string `json:"init,omitempty"`
	PageSize int64  `json:"page_size,omitempty"`
}

// Env is everything the tuner touches outside its own logic, so tests can run
// it against a fake tree.
type Env struct {
	Root    string // "" is the real system
	OnlyNet bool
	Facts   *FactsOverride
	Bin     string
	Out     io.Writer

	// Run runs an external command and returns its trimmed combined output.
	Run func(timeout time.Duration, name string, args ...string) (string, error)
	// Ran records every command, run or faked.
	Ran []string
	// FailWrite makes writes to the given absolute paths fail (tests).
	FailWrite map[string]error
	// PkgOwned says whether an OS package owns the file (nil: ask the
	// package manager).
	PkgOwned func(path string) bool
	// Deadline, when set, stops external commands from starting after it.
	Deadline time.Time

	// Eth reaches the NICs' driver settings. Under a fake root it is
	// hw.NoEthtool unless a test sets one.
	Eth hw.Ethtool
	// ForceNIC names the uplink devices instead of the default routes
	// (XUI_TUNE_NIC; tests only).
	ForceNIC []string
	// Clock and Probe drive the queue watchdog (tests replace them).
	Clock Clock
	Probe Prober

	owned   map[string]bool // package ownership, asked once per file
	stopped bool            // SIGTERM during a queue change: stop after it
}

// NewEnv builds the environment from the process environment.
func NewEnv() (*Env, error) {
	e := &Env{Out: os.Stdout}
	if r := os.Getenv("XUI_TUNE_ROOT"); r != "" {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		e.Root = filepath.Clean(abs)
	}
	e.OnlyNet = os.Getenv("XUI_TUNE_ONLY") == "net"
	if f := os.Getenv("XUI_TUNE_FACTS"); f != "" {
		e.Facts = &FactsOverride{}
		if err := json.Unmarshal([]byte(f), e.Facts); err != nil {
			return nil, fmt.Errorf("XUI_TUNE_FACTS: %w", err)
		}
	}
	e.Bin = os.Getenv("XUI_TUNE_BIN")
	if e.Bin == "" {
		e.Bin = "/usr/local/x-ui/x-ui"
		if exe, err := os.Executable(); err == nil && e.Root == "" {
			if r, err := filepath.EvalSymlinks(exe); err == nil {
				exe = r
			}
			if filepath.Base(exe) == "x-ui" {
				e.Bin = exe
			}
		}
	}
	if n := os.Getenv("XUI_TUNE_NIC"); n != "" && (e.Root != "" || e.OnlyNet) {
		for _, d := range strings.Split(n, ",") {
			if d = strings.TrimSpace(d); d != "" && !strings.ContainsAny(d, "/ ") {
				e.ForceNIC = append(e.ForceNIC, d)
			}
		}
	}
	e.Eth = hw.NoEthtool{}
	if e.Root == "" {
		e.Eth = hw.SystemEthtool()
		if e.OnlyNet {
			e.Eth = onlyDevs{e.Eth, e.ForceNIC}
		}
	}
	e.Run = e.realRun
	return e, nil
}

// onlyDevs refuses ethtool changes to any device but the named ones
// (XUI_TUNE_ONLY=net).
type onlyDevs struct {
	hw.Ethtool
	devs []string
}

func (o onlyDevs) allowed(dev string) error {
	for _, d := range o.devs {
		if d == dev {
			return nil
		}
	}
	return fmt.Errorf("ethtool %s: %w (XUI_TUNE_ONLY=net)", dev, syscall.EROFS)
}

func (o onlyDevs) SetChannels(dev string, c hw.Channels) error {
	if err := o.allowed(dev); err != nil {
		return err
	}
	return o.Ethtool.SetChannels(dev, c)
}

func (o onlyDevs) SetIndir(dev string, t []uint32) error {
	if err := o.allowed(dev); err != nil {
		return err
	}
	return o.Ethtool.SetIndir(dev, t)
}

func (o onlyDevs) SetFlowHash(dev string, f hw.Flow, bits uint64) error {
	if err := o.allowed(dev); err != nil {
		return err
	}
	return o.Ethtool.SetFlowHash(dev, f, bits)
}

// hw is the tree the hardware readers read.
func (e *Env) hw() hw.FS { return hw.FS{Root: e.Root} }

// eth is Eth, or no ethtool at all.
func (e *Env) eth() hw.Ethtool {
	if e.Eth == nil {
		return hw.NoEthtool{}
	}
	return e.Eth
}

// fake reports whether external commands are recorded instead of run.
func (e *Env) fake() bool { return e.Root != "" || e.OnlyNet }

func (e *Env) realRun(timeout time.Duration, name string, args ...string) (string, error) {
	e.Ran = append(e.Ran, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if e.fake() {
		return "", errNotRun
	}
	if !e.Deadline.IsZero() {
		left := time.Until(e.Deadline)
		if left <= 0 {
			return "", errors.New("deadline reached")
		}
		if left < timeout {
			timeout = left
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// run is Run with the default timeout.
func (e *Env) run(name string, args ...string) (string, error) {
	return e.Run(20*time.Second, name, args...)
}

// have reports whether a command exists (always false when faked, unless a
// test's Run answers for it).
func (e *Env) have(name string) bool {
	if e.fake() {
		_, err := e.Run(time.Second, "command", "-v", name)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// P maps an absolute system path into the root. It panics if the result
// would leave the root: a test must never touch the real system.
func (e *Env) P(abs string) string {
	if e.Root == "" {
		return abs
	}
	j := filepath.Join(e.Root, abs)
	if j != e.Root && !strings.HasPrefix(j, e.Root+string(os.PathSeparator)) {
		panic("tune: path escapes XUI_TUNE_ROOT: " + abs)
	}
	return j
}

func (e *Env) read(abs string) (string, error) {
	b, err := os.ReadFile(e.P(abs))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (e *Env) readTrim(abs string) string {
	s, err := e.read(abs)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func (e *Env) exists(abs string) bool {
	_, err := os.Lstat(e.P(abs))
	return err == nil
}

func (e *Env) isDir(abs string) bool {
	st, err := os.Stat(e.P(abs))
	return err == nil && st.IsDir()
}

// glob is filepath.Glob on system paths; results are system paths.
func (e *Env) glob(pattern string) []string {
	m, _ := filepath.Glob(e.P(pattern))
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, e.unP(p))
	}
	return out
}

func (e *Env) unP(p string) string {
	if e.Root == "" {
		return p
	}
	r := strings.TrimPrefix(p, e.Root)
	if r == "" {
		return "/"
	}
	return r
}

// readLink follows one symlink at abs, staying inside the root. It returns
// abs itself when abs is not a symlink.
func (e *Env) resolve(abs string) string {
	for i := 0; i < 8; i++ {
		t, err := os.Readlink(e.P(abs))
		if err != nil {
			return abs
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(abs), t)
		}
		abs = filepath.Clean(t)
	}
	return abs
}

// writable says whether a kernel file (sysctl, module parameter) can be
// written, without writing it.
func (e *Env) writable(abs string) error {
	if err, ok := e.FailWrite[abs]; ok && (errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrNotExist)) {
		return err // EPERM and EINVAL only show when writing
	}
	if e.OnlyNet && !e.netOnlyAllows(abs) {
		return syscall.EROFS
	}
	if e.Root != "" {
		if _, err := os.Stat(e.P(abs)); err != nil {
			return err
		}
		return nil
	}
	return unix.Access(abs, unix.W_OK)
}

// netOnlyAllows says which kernel files XUI_TUNE_ONLY=net may write: the
// network namespace's own sysctls and the test devices' queue files. Never
// an interrupt's affinity.
func (e *Env) netOnlyAllows(abs string) bool {
	if strings.HasPrefix(abs, "/proc/sys/net/") {
		return true
	}
	for _, n := range e.ForceNIC {
		if strings.HasPrefix(abs, "/sys/class/net/"+n+"/queues/") {
			return true
		}
	}
	return false
}

// writeKernel writes a value to a kernel file.
func (e *Env) writeKernel(abs, val string) error {
	if err, ok := e.FailWrite[abs]; ok {
		return err
	}
	if e.OnlyNet && !e.netOnlyAllows(abs) {
		return syscall.EROFS
	}
	flags := os.O_WRONLY
	if e.Root != "" {
		flags |= os.O_TRUNC // a regular file in the fake tree
	}
	f, err := os.OpenFile(e.P(abs), flags, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(val + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeFile writes one of x-ui's own files atomically, and only when its
// bytes change. It reports whether it wrote.
func (e *Env) writeFile(abs string, data []byte, mode os.FileMode) (bool, error) {
	p := e.P(abs)
	if old, err := os.ReadFile(p); err == nil && string(old) == string(data) {
		if st, err := os.Stat(p); err == nil && st.Mode().Perm() != mode {
			return true, os.Chmod(p, mode)
		}
		return false, nil
	}
	if err, ok := e.FailWrite[abs]; ok {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return false, err
	}
	return true, nil
}

// remove deletes a file; a missing file is not an error. It reports whether
// something was removed.
func (e *Env) remove(abs string) (bool, error) {
	err := os.Remove(e.P(abs))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// move renames a file, creating the target's directory.
func (e *Env) move(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(e.P(to)), 0o755); err != nil {
		return err
	}
	return os.Rename(e.P(from), e.P(to))
}

func (e *Env) printf(format string, a ...any) {
	if e.Out != nil {
		fmt.Fprintf(e.Out, format, a...)
	}
}
