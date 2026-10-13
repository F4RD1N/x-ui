package hw

import (
	"fmt"
	"strconv"
	"strings"
)

// IRQCount is one line of /proc/interrupts.
type IRQCount struct {
	IRQ    int
	Name   string         // the last column: the handler's name
	PerCPU map[int]uint64 // CPU -> interrupts handled there
}

// ReadInterrupts reads the numbered interrupts of /proc/interrupts. The
// header names the CPU columns (offline CPUs have none).
func ReadInterrupts(fs FS) (map[int]*IRQCount, error) {
	data, err := fs.Read("/proc/interrupts")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(data, "\n")
	var cols []int
	out := map[int]*IRQCount{}
	for i, l := range lines {
		f := strings.Fields(l)
		if i == 0 {
			for _, h := range f {
				n, err := strconv.Atoi(strings.TrimPrefix(h, "CPU"))
				if err != nil {
					return nil, fmt.Errorf("/proc/interrupts: bad header %q", h)
				}
				cols = append(cols, n)
			}
			continue
		}
		if len(f) == 0 {
			continue
		}
		irq, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		if err != nil || !strings.HasSuffix(f[0], ":") {
			continue // NMI, LOC, ...
		}
		c := &IRQCount{IRQ: irq, PerCPU: map[int]uint64{}}
		n := 0
		for j, cpu := range cols {
			if 1+j >= len(f) {
				break
			}
			v, err := strconv.ParseUint(f[1+j], 10, 64)
			if err != nil {
				break
			}
			c.PerCPU[cpu] = v
			n++
		}
		if 1+n < len(f) {
			c.Name = f[len(f)-1]
		}
		out[irq] = c
	}
	return out, nil
}

// ReadIRQAffinity reads an interrupt's CPUs: the ones it may run on, the ones
// it runs on (nil before Linux 4.15), and the driver's hint (empty when the
// driver gives none).
func ReadIRQAffinity(fs FS, irq int) (aff, eff, hint CPUSet) {
	d := fmt.Sprintf("/proc/irq/%d/", irq)
	if s, err := fs.Read(d + "smp_affinity_list"); err == nil {
		aff, _ = ParseList(s)
	} else if s, err := fs.Read(d + "smp_affinity"); err == nil {
		aff, _ = ParseMask(s)
	}
	if s, err := fs.Read(d + "effective_affinity_list"); err == nil {
		eff, _ = ParseList(s)
	}
	if s, err := fs.Read(d + "affinity_hint"); err == nil {
		hint, _ = ParseMask(s)
	}
	return aff, eff, hint
}

// DefaultIRQMask is the CPUs the kernel gives a new interrupt of a device on
// the node: the default affinity, limited to the online CPUs and, when that
// leaves any, to the node's CPUs (node < 0: no limit). Nil when the default
// affinity cannot be read.
func DefaultIRQMask(fs FS, node int, online CPUSet) CPUSet {
	m, err := ParseMask(fs.ReadTrim("/proc/irq/default_smp_affinity"))
	if err != nil {
		return nil
	}
	m = m.And(online)
	if node >= 0 {
		if nc, err := ParseList(fs.ReadTrim(fmt.Sprintf("%s/node%d/cpulist", nodeDir, node))); err == nil {
			if x := m.And(nc); len(x) > 0 {
				m = x
			}
		}
	}
	return m
}
