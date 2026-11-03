package guard

import (
	"testing"
	"time"
)

func TestGoContainsPanics(t *testing.T) {
	failed := make(chan struct{})
	Go(func() { panic("secret value") }, func() { close(failed) })
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("onPanic did not run")
	}
	done := make(chan struct{})
	Go(func() { panic("first") }, func() { defer close(done); panic("second") })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a panicking onPanic escaped")
	}
	ran := make(chan struct{})
	Go(func() { close(ran) }, func() { t.Error("onPanic ran without a panic") })
	<-ran
}
