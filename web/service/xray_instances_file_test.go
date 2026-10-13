package service

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// recordNICTrigger replaces the NIC trigger with a recorder and starts from
// a freshly started panel, with stopped as the instances stopped from the
// overview.
func recordNICTrigger(t *testing.T, stopped map[string]bool) *[]string {
	t.Helper()
	var calls []string
	oldTrigger := nicTrigger
	nicTrigger = func(path string) { calls = append(calls, path) }
	instFileMu.Lock()
	oldDone := instFileDone
	instFileDone = false
	instFileMu.Unlock()
	instMu.Lock()
	oldStopped := stoppedInst
	stoppedInst = stopped
	instMu.Unlock()
	t.Cleanup(func() {
		nicTrigger = oldTrigger
		instFileMu.Lock()
		instFileDone = oldDone
		instFileMu.Unlock()
		instMu.Lock()
		stoppedInst = oldStopped
		instMu.Unlock()
	})
	return &calls
}

func TestPublishInstances(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	calls := recordNICTrigger(t, map[string]bool{"xray-3": true})
	path := filepath.Join(dir, hw.InstancesFile)

	plan := &instancePlan{
		order: []string{"xray-1", "xray-2", "xray-3", "xray-10"},
		cores: map[string]int{"xray-1": 0, "xray-2": 2, "xray-3": 0, "xray-10": 0},
	}
	alloc := map[string][]int{"xray-1": {2, 3}, "xray-2": {0, 1}, "xray-10": {4, 5}}
	egress := map[string]string{"xray-2": "192.0.2.7"}

	publishInstances(alloc, plan, egress)
	got, err := hw.ReadInstances(hw.FS{}, path)
	if err != nil {
		t.Fatal(err)
	}
	want := &hw.Instances{Version: 1, Allowed: hw.NewCPUSet(xray.AvailableCPUs()...).List(), Instances: []hw.Instance{
		{Name: "xray-1", CPUs: "2-3", Config: filepath.Join(dir, "config-xray-1.json")},
		{Name: "xray-2", CPUs: "0-1", Cores: 2, Config: filepath.Join(dir, "config-xray-2.json"), Egress: "192.0.2.7"},
		{Name: "xray-10", CPUs: "4-5", Config: filepath.Join(dir, "config-xray-10.json")},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instances.json:\n got  %+v\n want %+v", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if !reflect.DeepEqual(*calls, []string{path}) {
		t.Fatalf("triggers after the first publish: %v", *calls)
	}

	// The same split again: no write, no trigger.
	publishInstances(alloc, plan, egress)
	same := func() bool {
		now, err := os.Stat(path)
		return err == nil && os.SameFile(fi, now)
	}
	if !same() || len(*calls) != 1 {
		t.Fatalf("unchanged split: rewritten %v, triggers %v", !same(), *calls)
	}

	// A panel restart: the file is right, but the interrupts are placed
	// once anyway.
	instFileMu.Lock()
	instFileDone = false
	instFileMu.Unlock()
	publishInstances(alloc, plan, egress)
	if !same() || len(*calls) != 2 {
		t.Fatalf("first publish after a restart: rewritten %v, triggers %v", !same(), *calls)
	}

	// A new split: written and triggered.
	alloc["xray-1"] = []int{2}
	publishInstances(alloc, plan, egress)
	if same() || len(*calls) != 3 {
		t.Fatalf("changed split: rewritten %v, triggers %v", !same(), *calls)
	}
	if got, _ := hw.ReadInstances(hw.FS{}, path); got == nil || got.Instances[0].CPUs != "2" {
		t.Fatalf("changed split: %+v", got)
	}
	// Nothing left behind but the file.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("bin folder: %v", entries)
	}
}

func TestPublishInstancesWriteFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	t.Setenv("XUI_BIN_FOLDER", dir)
	calls := recordNICTrigger(t, map[string]bool{})
	plan := &instancePlan{order: []string{"xray-1"}, cores: map[string]int{"xray-1": 0}}
	publishInstances(map[string][]int{"xray-1": {0}}, plan, nil)
	if len(*calls) != 0 || instFileDone {
		t.Fatalf("triggered without a file: %v", *calls)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("created %s", dir)
	}
}

func TestTuneNICOnlyFromXUI(t *testing.T) {
	// A test binary is not x-ui: it never runs "tune nic".
	if exe := xuiExecutable(); exe != "" {
		t.Fatalf("xuiExecutable = %q under go test", exe)
	}
	runTuneNIC(filepath.Join(t.TempDir(), hw.InstancesFile))
	tuneNICRuns.mu.Lock()
	running := tuneNICRuns.running
	tuneNICRuns.mu.Unlock()
	if running {
		t.Fatal("tune nic started")
	}
}

func TestCoalescer(t *testing.T) {
	c := &coalescer{}
	started := make(chan string, 10)
	release := make(chan struct{})
	var mu sync.Mutex
	var runs []string
	job := func(arg string) {
		started <- arg
		<-release
		mu.Lock()
		runs = append(runs, arg)
		mu.Unlock()
	}
	idle := func() {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			c.mu.Lock()
			running := c.running
			c.mu.Unlock()
			if !running {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("coalescer never went idle")
			}
		}
	}

	c.request("a", job)
	if got := <-started; got != "a" {
		t.Fatalf("first run %q", got)
	}
	// Three requests during the run make one more run, with the last.
	c.request("b", job)
	c.request("c", job)
	c.request("d", job)
	release <- struct{}{}
	if got := <-started; got != "d" {
		t.Fatalf("second run %q", got)
	}
	release <- struct{}{}
	idle()
	select {
	case arg := <-started:
		t.Fatalf("extra run %q", arg)
	default:
	}
	// Idle again: a request runs at once.
	c.request("e", job)
	if got := <-started; got != "e" {
		t.Fatalf("third run %q", got)
	}
	release <- struct{}{}
	idle()
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(runs, []string{"a", "d", "e"}) {
		t.Fatalf("runs %v", runs)
	}
}
