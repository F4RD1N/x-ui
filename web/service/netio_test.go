package service

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fakeNet builds a /sys/class/net: phys get a device link, ports a master
// link, and the named bridges and bonds their sysfs folders.
func fakeNet(t *testing.T, phys []string, ports map[string]string, bridges, bonds []string, others ...string) string {
	t.Helper()
	root := t.TempDir()
	mk := func(n string) {
		if err := os.MkdirAll(filepath.Join(root, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range append(append(append(append([]string{}, phys...), bridges...), bonds...), others...) {
		mk(n)
	}
	for _, n := range phys {
		if err := os.Symlink("../../../devices/pci0000:00/0000:00:01.0", filepath.Join(root, n, "device")); err != nil {
			t.Fatal(err)
		}
	}
	for p, m := range ports {
		mk(p)
		if err := os.Symlink("../"+m, filepath.Join(root, p, "master")); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range bridges {
		mk(filepath.Join(n, "bridge"))
	}
	for _, n := range bonds {
		mk(filepath.Join(n, "bonding"))
	}
	return root
}

func TestCountedInterfaces(t *testing.T) {
	lo := map[string]bool{"lo": true}
	cases := []struct {
		name  string
		root  string
		names []string
		want  []string
	}{
		{
			// fra-bl73s3: a byte through bond0 also passes eno1 or eno2.
			name:  "bond of two ports counts the bond once",
			root:  fakeNet(t, []string{"eno1", "eno2"}, map[string]string{"eno1": "bond0", "eno2": "bond0"}, nil, []string{"bond0"}, "lo"),
			names: []string{"lo", "eno1", "eno2", "bond0"},
			want:  []string{"bond0"},
		},
		{
			name:  "single NIC, a second one unplugged, loopback left out",
			root:  fakeNet(t, []string{"eno1", "eno2"}, nil, nil, nil, "lo"),
			names: []string{"lo", "eno1", "eno2"},
			want:  []string{"eno1", "eno2"},
		},
		{
			// The bridge and the containers' veths carry what eth0 counts.
			name:  "docker bridge, veths, wireguard and a VLAN are left out",
			root:  fakeNet(t, []string{"eth0"}, map[string]string{"veth1a2b": "docker0"}, []string{"docker0"}, nil, "lo", "wg0", "eth0.100"),
			names: []string{"lo", "eth0", "docker0", "veth1a2b", "wg0", "eth0.100"},
			want:  []string{"eth0"},
		},
		{
			// A host whose NIC is a bridge port (VMs behind br0): the NIC counts.
			name:  "physical NIC in a bridge is counted itself",
			root:  fakeNet(t, []string{"enp3s0"}, map[string]string{"enp3s0": "br0", "tap0": "br0"}, []string{"br0"}, nil, "lo"),
			names: []string{"lo", "enp3s0", "br0", "tap0"},
			want:  []string{"enp3s0"},
		},
		{
			// Inside a container nothing is physical: its own interfaces count.
			name:  "container: no physical NIC, every non-loopback interface",
			root:  fakeNet(t, nil, nil, nil, nil, "lo", "eth0"),
			names: []string{"lo", "eth0"},
			want:  []string{"eth0"},
		},
	}
	for _, c := range cases {
		got := countedInterfaces(c.root, c.names, lo)
		want := map[string]bool{}
		for _, n := range c.want {
			want[n] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: counted %v, want %v", c.name, got, want)
		}
	}
}

// On this machine: no interface is counted twice and loopback never is.
func TestHostNetCountersHere(t *testing.T) {
	if _, err := os.Stat(sysClassNet); err != nil {
		t.Skip("no", sysClassNet)
	}
	if _, _, err := hostNetCounters(); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(sysClassNet)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	counted := countedInterfaces(sysClassNet, names, loopbackNames())
	for n := range counted {
		if loopbackNames()[n] {
			t.Errorf("loopback %s counted", n)
		}
		if m := masterOf(sysClassNet, n); m != "" && counted[m] {
			t.Errorf("%s and its master %s both counted", n, m)
		}
	}
}
