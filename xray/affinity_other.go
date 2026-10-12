//go:build !linux

package xray

// AvailableCPUs lists the CPUs cores can be given. Pinning is Linux-only;
// elsewhere every core simply shares all CPUs.
func AvailableCPUs() []int { return sequentialCPUs() }

func pinCurrentThread(cpus []int) error { return nil }

func pinProcess(pid int, cpus []int) error { return nil }

// ProcessCPUs is not available outside Linux.
func ProcessCPUs(pid int) []int { return nil }
