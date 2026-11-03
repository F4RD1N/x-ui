//go:build !without_native_protocols

package anytls_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func reapGoroutines() int {
	b := make([]byte, 1<<20)
	n := runtime.Stack(b, true)
	return strings.Count(string(b[:n]), "anytls.(*Client).reap(")
}

func load(t *testing.T, j string) (*core.Instance, error) {
	cfg, err := serial.LoadJSONConfig(strings.NewReader(j))
	if err != nil {
		t.Fatalf("conf: %v", err)
	}
	return core.New(cfg)
}

// Building an AnyTLS outbound starts nothing, so a core.New that fails after
// building it (here a duplicate tag) leaves no goroutine behind.
func TestAnyTLSNoReaperOnFailedLoad(t *testing.T) {
	before := reapGoroutines()
	for i := 0; i < 5; i++ {
		inst, err := load(t, `{"outbounds":[
		 {"tag":"proxy","protocol":"anytls","settings":{"address":"127.0.0.1","port":9,"password":"x"}},
		 {"tag":"proxy","protocol":"freedom"}]}`)
		if err == nil {
			inst.Close()
			t.Fatal("expected core.New to fail on the duplicate tag")
		}
	}
	inst, err := load(t, `{"outbounds":[{"tag":"proxy","protocol":"anytls","settings":{"address":"127.0.0.1","port":9,"password":"x"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if err = inst.Start(); err != nil {
		t.Fatal(err)
	}
	inst.Close()
	time.Sleep(100 * time.Millisecond)
	if after := reapGoroutines(); after != before {
		t.Fatalf("AnyTLS reap goroutines before=%d after=%d", before, after)
	}
}
