package session

import (
	"context"
	"testing"
)

func TestOpenVPNMuxMetadata(t *testing.T) {
	base := context.Background()
	if MuxStreamFromContext(base) {
		t.Fatal("ordinary request marked mux")
	}
	type key struct{}
	ctx := ContextWithMuxStream(context.WithValue(base, key{}, "preserved"))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !MuxStreamFromContext(ctx) || ctx.Value(key{}) != "preserved" {
		t.Fatal("metadata did not survive context derivation")
	}
	if MuxStreamFromContext(base) {
		t.Fatal("mark mutated ancestor context")
	}
	if !MuxStreamFromContext(SubContextFromMuxInbound(ctx)) {
		t.Fatal("metadata lost in outbound subcontext")
	}
}
