package hw

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	for in, want := range map[string]string{
		"0-3,8":        "0-3,8",
		"0-27,56-83\n": "0-27,56-83",
		"5":            "5",
		"3,1,2":        "1-3",
		"0-1":          "0-1",
		"1,3,5":        "1,3,5",
		"":             "",
		"(null)":       "",
		"  (null)\n":   "",
	} {
		c, err := ParseList(in)
		if err != nil || c.List() != want {
			t.Errorf("ParseList(%q) = %v %q, %v", in, c, c.List(), err)
		}
	}
	for _, bad := range []string{"3-1", "a", "1-", "-1", "0-99999"} {
		if _, err := ParseList(bad); err == nil {
			t.Errorf("ParseList(%q): no error", bad)
		}
	}
}

func TestMask(t *testing.T) {
	odd := NewCPUSet()
	for c := 1; c < 56; c += 2 {
		odd = append(odd, c)
	}
	all := func(n int) CPUSet {
		var s CPUSet
		for i := 0; i < n; i++ {
			s = append(s, i)
		}
		return s
	}
	for _, c := range []struct {
		set   CPUSet
		nbits int
		want  string
	}{
		{all(8), 8, "ff"},
		{nil, 8, "00"},
		{NewCPUSet(2), 8, "04"},
		{NewCPUSet(0), 56, "000000,00000001"},
		{all(56), 56, "ffffff,ffffffff"},
		{odd, 56, "aaaaaa,aaaaaaaa"},
		{all(32), 32, "ffffffff"},
		{all(33), 33, "1,ffffffff"},
		{NewCPUSet(40), 8, "100,00000000"}, // wider than nbits: as wide as the set needs
		{nil, 0, "0"},
		{NewCPUSet(511), 512, "80000000" + strings.Repeat(",00000000", 15)},
	} {
		if got := c.set.Mask(c.nbits); got != c.want {
			t.Errorf("%v.Mask(%d) = %q, want %q", c.set, c.nbits, got, c.want)
		}
		back, err := ParseMask(c.want)
		if err != nil || !back.Equal(c.set) {
			t.Errorf("ParseMask(%q) = %v, %v", c.want, back, err)
		}
	}
	if m, err := ParseMask("ff,ffffffff\n"); err != nil || m.List() != "0-39" {
		t.Errorf("ParseMask: %v %v", m, err)
	}
	for _, bad := range []string{"", "xyz", "1,,2", "123456789"} {
		if _, err := ParseMask(bad); err == nil {
			t.Errorf("ParseMask(%q): no error", bad)
		}
	}
}

// Lists and masks of random sets up to 512 CPUs read back unchanged, at the
// kernel's width and at any wider one.
func TestCPUSetRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		n := 1 + r.Intn(512)
		var cpus []int
		for j := r.Intn(n + 1); j > 0; j-- {
			cpus = append(cpus, r.Intn(n))
		}
		s := NewCPUSet(cpus...)
		l, err := ParseList(s.List())
		if err != nil || !l.Equal(s) {
			t.Fatalf("list %q: %v %v", s.List(), l, err)
		}
		for _, w := range []int{n, 512} {
			m, err := ParseMask(s.Mask(w))
			if err != nil || !m.Equal(s) {
				t.Fatalf("mask %q: %v %v", s.Mask(w), m, err)
			}
		}
		// 8 digits a group and a comma before it, the first group only as
		// many digits as its bits need.
		first := ((n-1)%32 + 1 + 3) / 4
		if got, want := len(s.Mask(n)), first+((n+31)/32-1)*9; got != want {
			t.Fatalf("mask width for %d bits: %d, want %d (%q)", n, got, want, s.Mask(n))
		}
	}
}

func TestCPUSetOps(t *testing.T) {
	a, b := NewCPUSet(5, 1, 3, 3, -1), NewCPUSet(3, 4, 5)
	if a.List() != "1,3,5" {
		t.Fatalf("NewCPUSet: %v", a)
	}
	if a.And(b).List() != "3,5" || a.Minus(b).List() != "1" || a.Union(b).List() != "1,3-5" {
		t.Errorf("ops: and %v minus %v union %v", a.And(b), a.Minus(b), a.Union(b))
	}
	if !a.Has(3) || a.Has(4) || !CPUSet(nil).Equal(CPUSet{}) || a.Equal(b) {
		t.Error("Has/Equal")
	}
	if a.List() != "1,3,5" {
		t.Error("ops changed the operand")
	}
}

func TestCPUSetJSON(t *testing.T) {
	b, err := json.Marshal(map[string]CPUSet{"a": NewCPUSet(0, 1, 2, 3, 8), "b": nil})
	if err != nil || string(b) != `{"a":"0-3,8","b":""}` {
		t.Fatalf("%s %v", b, err)
	}
	var back map[string]CPUSet
	if err := json.Unmarshal(b, &back); err != nil || back["a"].List() != "0-3,8" || len(back["b"]) != 0 {
		t.Fatalf("%v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"a":"x"}`), &back); err == nil {
		t.Fatal("bad list accepted")
	}
}
