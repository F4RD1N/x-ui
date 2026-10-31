package memlimit

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const GiB = 1 << 30

// kernelTCP is the kernel's default tcp_mem ceiling for mem: about 3/32 of it.
func kernelTCP(mem int64) int64 { return mem * 3 / 32 }

func TestLimit(t *testing.T) {
	cases := []struct {
		name   string
		f      Facts
		lo, hi int64 // in MiB
	}{
		// a Hetzner 1 GB server (MemTotal 954000 kB)
		{"1 GB server", Facts{MemTotal: 954000 << 10, TCPMemMax: kernelTCP(954000 << 10)}, 430, 445},
		// the same server's snapshot booted with 24 GB
		{"24 GB server", Facts{MemTotal: 24 * 1000 * 1000 << 10, TCPMemMax: kernelTCP(24 * 1000 * 1000 << 10)}, 14800, 15200},
		{"4 GB server", Facts{MemTotal: 4 * GiB, TCPMemMax: kernelTCP(4 * GiB)}, 2580, 2600},
		// Docker --memory 1g on a 16 GiB machine, tcp_mem not visible in the
		// container's network namespace: the same as a 1 GiB machine
		{"1 GiB container", Facts{MemTotal: 16 * GiB, Cgroup: 1 * GiB}, 504, 504},
		// MemoryMax=2G on x-ui.service of a 64 GiB server: its share of tcp_mem
		{"2 GiB service limit", Facts{MemTotal: 64 * GiB, Cgroup: 2 * GiB, TCPMemMax: kernelTCP(64 * GiB)}, 1200, 1200},
		// a tuning script's tcp_mem of 100 GiB on 8 GiB: a quarter is counted
		{"tcp_mem above the memory", Facts{MemTotal: 8 * GiB, TCPMemMax: 100 * GiB}, 4300, 4300},
		{"never under 256 MiB", Facts{MemTotal: 512 << 20}, 256, 256},
	}
	for _, c := range cases {
		got := Limit(c.f) / MiB
		if got < c.lo || got > c.hi {
			t.Errorf("%s: %d MiB, want %d-%d", c.name, got, c.lo, c.hi)
		}
		if Limit(c.f)%MiB != 0 {
			t.Errorf("%s: %d is not whole MiB", c.name, Limit(c.f))
		}
	}
	if got := Limit(Facts{}); got != 0 {
		t.Errorf("memory unknown: %d, want 0", got)
	}
	if got := Limit(Facts{Cgroup: 1 * GiB}); got/MiB != 504 {
		t.Errorf("only a cgroup limit known: %d MiB, want 504", got/MiB)
	}
}

func TestEnviron(t *testing.T) {
	env := []string{"PATH=/bin", "GOMEMLIMIT=449MiB", "XRAY_VMESS_AEAD_FORCED=false", "GOMEMLIMIT=1GiB", "GOMEMLIMITX=keep", "GOGC=Off"}
	got := Environ(env, 15000*MiB)
	want := []string{"PATH=/bin", "XRAY_VMESS_AEAD_FORCED=false", "GOMEMLIMITX=keep", "GOMEMLIMIT=15000MiB"}
	if !slices.Equal(got, want) {
		t.Errorf("Environ = %q, want %q", got, want)
	}
	if env[1] != "GOMEMLIMIT=449MiB" {
		t.Errorf("the caller's slice was changed: %q", env)
	}
	if got := Environ([]string{"GOGC=150"}, 256*MiB); !slices.Equal(got, []string{"GOGC=150", "GOMEMLIMIT=256MiB"}) {
		t.Errorf("a GOGC with a number is kept: %q", got)
	}
	if got := Environ(env, 0); !slices.Equal(got, env) {
		t.Errorf("limit 0 changed the environment: %q", got)
	}
}

// write puts content at root+p.
func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetect(t *testing.T) {
	page := int64(os.Getpagesize())
	meminfo := "MemTotal:       24000000 kB\nMemFree:        20000000 kB\n"

	t.Run("a VM, no limits", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "/proc/meminfo", meminfo)
		write(t, root, "/proc/sys/net/ipv4/tcp_mem", "281250\t375000\t562500\n")
		write(t, root, "/proc/self/cgroup", "0::/system.slice/x-ui.service\n")
		write(t, root, "/sys/fs/cgroup/system.slice/x-ui.service/memory.max", "max\n")
		write(t, root, "/sys/fs/cgroup/system.slice/memory.max", "max\n")
		f := detect(root)
		want := Facts{MemTotal: 24000000 << 10, TCPMemMax: 562500 * page}
		if f != want {
			t.Errorf("detect = %+v, want %+v", f, want)
		}
		if s := f.String(); s != "22.9 GiB RAM" {
			t.Errorf("String = %q", s)
		}
	})

	t.Run("MemoryMax on the service, a smaller one above it", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "/proc/meminfo", meminfo)
		write(t, root, "/proc/self/cgroup", "0::/system.slice/x-ui.service\n")
		write(t, root, "/sys/fs/cgroup/system.slice/x-ui.service/memory.max", "4294967296\n")
		write(t, root, "/sys/fs/cgroup/system.slice/memory.max", "3221225472\n")
		f := detect(root)
		if f.Cgroup != 3*GiB || f.TCPMemMax != 0 {
			t.Errorf("detect = %+v, want cgroup 3 GiB and no tcp_mem", f)
		}
		if s := f.String(); s != "memory limit 3.0 GiB of 22.9 GiB RAM" {
			t.Errorf("String = %q", s)
		}
	})

	t.Run("cgroup v1 container: host path, own mount", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "/proc/meminfo", meminfo)
		write(t, root, "/proc/self/cgroup", "12:pids:/docker/abc\n4:cpu,memory:/docker/abc\n1:name=systemd:/docker/abc\n")
		write(t, root, "/sys/fs/cgroup/memory/memory.limit_in_bytes", "1073741824\n")
		if f := detect(root); f.Cgroup != 1*GiB {
			t.Errorf("detect = %+v, want cgroup 1 GiB", f)
		}
	})

	t.Run("v1 without a limit", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "/proc/meminfo", meminfo)
		write(t, root, "/proc/self/cgroup", "4:memory:/system.slice/x-ui.service\n")
		write(t, root, "/sys/fs/cgroup/memory/system.slice/x-ui.service/memory.limit_in_bytes", "9223372036854771712\n")
		if f := detect(root); f.Cgroup != 0 {
			t.Errorf("detect = %+v, want no cgroup limit", f)
		}
	})

	t.Run("nothing readable", func(t *testing.T) {
		if f := detect(t.TempDir()); f != (Facts{}) || Limit(f) != 0 {
			t.Errorf("detect = %+v", f)
		}
	})
}

// This machine's own files parse into something sane.
func TestDetectHere(t *testing.T) {
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skip("no /proc/meminfo")
	}
	f := Detect()
	lim := Limit(f)
	t.Logf("%s: GOMEMLIMIT=%dMiB", f, lim/MiB)
	if f.MemTotal <= 0 || lim < 256*MiB || lim > f.Usable() {
		t.Errorf("Detect = %+v, Limit %d", f, lim)
	}
	if !strings.HasSuffix(Environ(nil, lim)[0], "MiB") {
		t.Error("Environ does not write MiB")
	}
}
