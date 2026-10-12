//go:build linux

package xray

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// AvailableCPUs lists the CPUs this panel may run on, which are the CPUs its
// cores can be given. It is read once, when the panel starts: a core is
// started from a thread pinned to that core's CPUs, and Go may run that
// goroutine on the main thread, so the panel's own mask cannot be read
// reliably afterwards.
func AvailableCPUs() []int {
	return append([]int(nil), panelCPUs...)
}

var panelCPUs = readPanelCPUs()

func readPanelCPUs() []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(os.Getpid(), &set); err != nil {
		return sequentialCPUs()
	}
	var cpus []int
	for i := 0; i < 1024; i++ { // CPU_SETSIZE
		if set.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	if len(cpus) == 0 {
		return sequentialCPUs()
	}
	return cpus
}

func cpuSet(cpus []int) *unix.CPUSet {
	var set unix.CPUSet
	set.Zero()
	for _, c := range cpus {
		set.Set(c)
	}
	return &set
}

// pinCurrentThread restricts the calling OS thread to cpus. A child forked
// from it inherits the mask, so a core started from a pinned thread is pinned
// from its first instruction, before its runtime starts any other thread.
// The caller must hold runtime.LockOSThread.
func pinCurrentThread(cpus []int) error {
	return unix.SchedSetaffinity(0, cpuSet(cpus))
}

// pinProcess moves every thread of a running process onto cpus. Threads
// created later inherit the mask from the thread that creates them, so a
// pass that finds every thread already pinned is final; a thread born during
// a pass is caught by the next one.
func pinProcess(pid int, cpus []int) error {
	set := cpuSet(cpus)
	var lastErr error
	for pass := 0; pass < 5; pass++ {
		tasks, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "task"))
		if err != nil {
			return err
		}
		changed := false
		for _, t := range tasks {
			tid, err := strconv.Atoi(t.Name())
			if err != nil {
				continue
			}
			var cur unix.CPUSet
			if unix.SchedGetaffinity(tid, &cur) == nil && cur == *set {
				continue
			}
			if err := unix.SchedSetaffinity(tid, set); err != nil {
				// The thread may have exited between listing and pinning.
				if err != unix.ESRCH {
					lastErr = err
				}
				continue
			}
			changed = true
		}
		if !changed {
			return lastErr
		}
	}
	return lastErr
}

// ProcessCPUs returns the CPUs a running process's main thread may use.
func ProcessCPUs(pid int) []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(pid, &set); err != nil {
		return nil
	}
	var cpus []int
	for i := 0; i < 1024; i++ { // CPU_SETSIZE
		if set.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	return cpus
}
