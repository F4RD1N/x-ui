package hw_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

func TestInstancesFile(t *testing.T) {
	if p := hw.InstancesPath("/usr/local/x-ui/bin"); p != "/usr/local/x-ui/bin/instances.json" {
		t.Fatalf("path %s", p)
	}
	s := &hw.Instances{Allowed: "0-55", Instances: []hw.Instance{
		{Name: "xray-1", CPUs: "1,3,5,29,31", Cores: 5, Config: "/usr/local/x-ui/bin/config-xray-1.json", Egress: "76.164.201.35"},
		{Name: "xray-2", CPUs: "", Cores: 0, Config: "/usr/local/x-ui/bin/config-xray-2.json"},
	}}
	data := s.Marshal()
	want := `{
  "version": 1,
  "allowed": "0-55",
  "instances": [
    {
      "name": "xray-1",
      "cpus": "1,3,5,29,31",
      "cores": 5,
      "config": "/usr/local/x-ui/bin/config-xray-1.json",
      "egress": "76.164.201.35"
    },
    {
      "name": "xray-2",
      "cpus": "",
      "cores": 0,
      "config": "/usr/local/x-ui/bin/config-xray-2.json"
    }
  ]
}
`
	if string(data) != want {
		t.Fatalf("marshal:\n%s", data)
	}
	if string(s.Marshal()) != want || s.Version != 0 {
		t.Fatal("Marshal is not deterministic, or changed its receiver")
	}
	root := t.TempDir()
	p := "/usr/local/x-ui/bin/instances.json"
	os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
	os.WriteFile(filepath.Join(root, p), data, 0o644)
	got, err := hw.ReadInstances(hw.FS{Root: root}, p)
	if err != nil {
		t.Fatal(err)
	}
	s.Version = 1
	if !reflect.DeepEqual(got, s) {
		t.Errorf("read back: %+v", got)
	}
	if e := (&hw.Instances{}).Marshal(); !strings.Contains(string(e), `"instances": []`) {
		t.Errorf("empty: %s", e)
	}
	for _, bad := range []string{`{"version": 2, "instances": []}`, `{"instances": []}`, `{`} {
		os.WriteFile(filepath.Join(root, p), []byte(bad), 0o644)
		if _, err := hw.ReadInstances(hw.FS{Root: root}, p); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
	if _, err := hw.ReadInstances(hw.FS{Root: root}, "/nope.json"); !os.IsNotExist(err) {
		t.Errorf("missing: %v", err)
	}
}

func TestFS(t *testing.T) {
	root := t.TempDir()
	fs := hw.FS{Root: root}
	defer func() {
		if recover() == nil {
			t.Error("a path escaping the root did not panic")
		}
	}()
	os.MkdirAll(filepath.Join(root, "/sys/devices/a/b"), 0o755)
	os.WriteFile(filepath.Join(root, "/sys/devices/a/b/f"), []byte(" x \n"), 0o644)
	os.MkdirAll(filepath.Join(root, "/sys/class/net"), 0o755)
	os.Symlink("../../devices/a/b", filepath.Join(root, "/sys/class/net/eth0"))
	os.Symlink("/sys/devices/a", filepath.Join(root, "/sys/abs")) // absolute: inside the root
	os.Symlink("loop", filepath.Join(root, "/sys/loop"))
	if fs.ReadTrim("/sys/class/net/eth0/f") != "x" || !fs.Exists("/sys/class/net/eth0") || fs.Exists("/sys/none") {
		t.Error("read through a relative link")
	}
	if r := fs.Resolve("/sys/class/net/eth0/f"); r != "/sys/devices/a/b/f" {
		t.Errorf("Resolve: %s", r)
	}
	if r := fs.Resolve("/sys/abs/b/../b/f"); r != "/sys/devices/a/b/f" {
		t.Errorf("Resolve absolute: %s", r)
	}
	if r := fs.Resolve("/sys/class/net/eth0/missing/x"); r != "/sys/devices/a/b/missing/x" {
		t.Errorf("Resolve missing: %s", r)
	}
	if r := fs.Resolve("/sys/loop"); r != "/sys/loop" {
		t.Errorf("Resolve loop: %s", r)
	}
	if fs.LinkBase("/sys/class/net/eth0") != "b" || fs.LinkBase("/sys/devices/a") != "" {
		t.Error("LinkBase")
	}
	if g := fs.Glob("/sys/class/net/*"); len(g) != 1 || g[0] != "/sys/class/net/eth0" {
		t.Errorf("Glob: %v", g)
	}
	if d := fs.ReadDir("/sys"); strings.Join(d, ",") != "abs,class,devices,loop" || fs.ReadDir("/none") != nil {
		t.Errorf("ReadDir: %v", d)
	}
	t.Setenv("XUI_HW_ROOT", root+"/sys/..")
	if hw.EnvFS().Root != root {
		t.Errorf("EnvFS: %q", hw.EnvFS().Root)
	}
	t.Setenv("XUI_HW_ROOT", "")
	if hw.EnvFS().Root != "" {
		t.Error("EnvFS without the variable")
	}
	fs.P("/../etc/passwd")
}
