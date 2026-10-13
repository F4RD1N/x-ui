package hw

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// maxCPU bounds what the parsers accept, so a bad file cannot make them
// allocate without end. Linux supports at most 8192 CPUs.
const maxCPU = 1 << 16

// CPUSet is a set of CPU numbers, sorted and without duplicates.
type CPUSet []int

// NewCPUSet makes a set from any CPU numbers (negative ones are dropped).
func NewCPUSet(cpus ...int) CPUSet {
	out := make(CPUSet, 0, len(cpus))
	for _, c := range cpus {
		if c >= 0 {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ParseList reads a kernel CPU list ("0-3,8"). "" and "(null)" are the empty
// set.
func ParseList(s string) (CPUSet, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "(null)" {
		return nil, nil
	}
	var out CPUSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 || a >= maxCPU {
			return nil, fmt.Errorf("bad CPU list %q", s)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b >= maxCPU {
				return nil, fmt.Errorf("bad CPU list %q", s)
			}
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	return NewCPUSet(out...), nil
}

// ParseMask reads a kernel CPU mask: 32-bit hex groups, most significant
// first, joined by commas ("ff,ffffffff").
func ParseMask(s string) (CPUSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty CPU mask")
	}
	groups := strings.Split(s, ",")
	if len(groups)*32 > maxCPU {
		return nil, fmt.Errorf("CPU mask too long")
	}
	var out CPUSet
	for i := len(groups) - 1; i >= 0; i-- {
		g := groups[i]
		if g == "" || len(g) > 8 {
			return nil, fmt.Errorf("bad CPU mask %q", s)
		}
		v, err := strconv.ParseUint(g, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("bad CPU mask %q", s)
		}
		base := (len(groups) - 1 - i) * 32
		for b := 0; b < 32; b++ {
			if v&(1<<b) != 0 {
				out = append(out, base+b)
			}
		}
	}
	return out, nil
}

// List is the compact kernel list form ("0-3,8"), "" for the empty set.
func (c CPUSet) List() string {
	var b strings.Builder
	for i := 0; i < len(c); {
		j := i
		for j+1 < len(c) && c[j+1] == c[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(c[i]))
		if j > i {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(c[j]))
		}
		i = j + 1
	}
	return b.String()
}

// Mask is the set in the kernel's mask format over max(nbits, highest CPU+1)
// bits (nbits is nr_cpu_ids for a mask as the kernel prints it): 32-bit hex
// groups, most significant first, joined by commas; the first group has as
// many digits as its bits need, the others 8.
func (c CPUSet) Mask(nbits int) string {
	if len(c) > 0 && c[len(c)-1]+1 > nbits {
		nbits = c[len(c)-1] + 1
	}
	if nbits < 1 {
		nbits = 1
	}
	groups := make([]uint32, (nbits+31)/32)
	for _, cpu := range c {
		groups[cpu/32] |= 1 << (cpu % 32)
	}
	var b strings.Builder
	first := nbits % 32
	if first == 0 {
		first = 32
	}
	for i := len(groups) - 1; i >= 0; i-- {
		width := 8
		if i == len(groups)-1 {
			width = (first + 3) / 4
		} else {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%0*x", width, groups[i])
	}
	return b.String()
}

// MarshalText writes the set as a list, so JSON shows "0-3,8".
func (c CPUSet) MarshalText() ([]byte, error) { return []byte(c.List()), nil }

// UnmarshalText reads a list.
func (c *CPUSet) UnmarshalText(b []byte) error {
	s, err := ParseList(string(b))
	if err != nil {
		return err
	}
	*c = s
	return nil
}

// Has reports whether cpu is in the set.
func (c CPUSet) Has(cpu int) bool {
	_, ok := slices.BinarySearch(c, cpu)
	return ok
}

// And is the intersection.
func (c CPUSet) And(o CPUSet) CPUSet {
	var out CPUSet
	for _, x := range c {
		if o.Has(x) {
			out = append(out, x)
		}
	}
	return out
}

// Minus is c without o's CPUs.
func (c CPUSet) Minus(o CPUSet) CPUSet {
	var out CPUSet
	for _, x := range c {
		if !o.Has(x) {
			out = append(out, x)
		}
	}
	return out
}

// Union is c and o together.
func (c CPUSet) Union(o CPUSet) CPUSet {
	return NewCPUSet(append(slices.Clone(c), o...)...)
}

// Equal compares two sets (nil and empty are equal).
func (c CPUSet) Equal(o CPUSet) bool {
	return slices.Equal(c, o)
}
