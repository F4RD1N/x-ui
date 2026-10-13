package service

// The CPU split, published for the NIC tuning.
//
// A NIC queue's interrupt and its packet work run on the CPU the interrupt
// is pinned to, and that CPU belongs to some xray instance. So after every
// apply the panel writes bin/instances.json with the CPUs each instance runs
// on, and when the split changed (or it is the panel's first apply) asks
// "x-ui tune nic" to line the queue interrupts up with it, so that no
// instance carries more than its share. "x-ui diag" reads the file too.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

var (
	instFileMu sync.Mutex
	// instFileDone is set once the file was published and the NIC tuning
	// asked since the panel started: a split the file already holds still
	// needs placing once after a restart (a reboot renumbers interrupts).
	instFileDone bool
)

// nicTrigger asks the NIC tuning to follow the split in path. Tests replace
// it.
var nicTrigger = runTuneNIC

// publishInstances writes instances.json for the instances that run (all
// the planned ones but those stopped from the overview), and triggers the
// NIC tuning when its bytes changed or on the first publish. Failing to
// write it is only logged: the cores run either way.
func publishInstances(alloc map[string][]int, plan *instancePlan, egress map[string]string) {
	s := &hw.Instances{Version: 1, Allowed: hw.NewCPUSet(xray.AvailableCPUs()...).List()}
	instMu.RLock()
	for _, name := range plan.order {
		if stoppedInst[name] {
			continue
		}
		cfg := instanceConfigPath(name)
		if abs, err := filepath.Abs(cfg); err == nil {
			cfg = abs
		}
		s.Instances = append(s.Instances, hw.Instance{
			Name:   name,
			CPUs:   hw.NewCPUSet(alloc[name]...).List(),
			Cores:  plan.cores[name],
			Config: cfg,
			Egress: egress[name],
		})
	}
	instMu.RUnlock()

	path := hw.InstancesPath(config.GetBinFolderPath())
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	instFileMu.Lock()
	defer instFileMu.Unlock()
	changed, err := writeFileIfChanged(path, s.Marshal(), 0o644)
	if err != nil {
		logger.Warning("write", path, ":", err)
		return
	}
	if changed || !instFileDone {
		instFileDone = true
		nicTrigger(path)
	}
}

// writeFileIfChanged replaces path with data through a temporary file and a
// rename, so a reader never sees half a file; it leaves a file that already
// holds data alone.
func writeFileIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	return true, nil
}

// tuneNICTimeout bounds one "x-ui tune nic" run.
const tuneNICTimeout = 20 * time.Second

var tuneNICRuns = &coalescer{}

// runTuneNIC runs "x-ui tune nic --quiet --instances path" in the
// background. It does nothing off Linux, without root, or when this program
// is not x-ui (a test binary): the NIC tuning is x-ui's own subcommand.
func runTuneNIC(path string) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}
	exe := xuiExecutable()
	if exe == "" {
		return
	}
	tuneNICRuns.request(path, func(path string) { execTuneNIC(exe, path) })
}

// xuiExecutable is this program's path when it is x-ui, else "".
func xuiExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil || filepath.Base(exe) != "x-ui" {
		return ""
	}
	return exe
}

func execTuneNIC(exe, path string) {
	ctx, cancel := context.WithTimeout(context.Background(), tuneNICTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "tune", "nic", "--quiet", "--instances", path).CombinedOutput()
	if s := strings.TrimSpace(string(out)); s != "" {
		logger.Info("x-ui tune nic:", s)
	}
	if err != nil {
		logger.Warning("x-ui tune nic:", err)
	}
}

// coalescer runs a job in the background, one run at a time. A request
// made while a run is going makes exactly one more run after it, with the
// latest argument, however many requests came: each run reads the current
// state, so the requests in between need no run of their own.
type coalescer struct {
	mu      sync.Mutex
	running bool
	pending bool
	arg     string
	job     func(string)
}

func (c *coalescer) request(arg string, job func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.arg, c.job = arg, job
	if c.running {
		c.pending = true
		return
	}
	c.running = true
	go c.loop()
}

func (c *coalescer) loop() {
	for {
		c.mu.Lock()
		arg, job := c.arg, c.job
		c.pending = false
		c.mu.Unlock()
		job(arg)
		c.mu.Lock()
		if !c.pending {
			c.running = false
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}
