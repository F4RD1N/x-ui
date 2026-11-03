package session

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestSharedSocketAllocatorAcrossPhysicalConnections(t *testing.T) {
	var next atomic.Uint32
	allocator := func() (uint32, error) { return next.Add(1), nil }
	c1, s1 := pair(t, Options{}, allocator)
	c2, s2 := pair(t, Options{}, allocator)
	a, b := openPair(t, c1, s1)
	defer a.Close()
	defer b.Close()
	c, d := openPair(t, c2, s2)
	defer c.Close()
	defer d.Close()
	if a.ID() != 1 || b.ID() != 1 || c.ID() != 2 || d.ID() != 2 {
		t.Fatalf("IDs %d %d %d %d", a.ID(), b.ID(), c.ID(), d.ID())
	}
}

func TestAllocatorRejectsZeroDuplicateAndPropagatesError(t *testing.T) {
	var id uint32
	var allocateErr error
	c, s := pair(t, Options{}, func() (uint32, error) { return id, allocateErr })
	if _, err := c.Open(context.Background(), "192.0.2.1", 443); err == nil {
		t.Fatal("zero ID accepted")
	}
	id = 9
	a, b := openPair(t, c, s)
	if _, err := c.Open(context.Background(), "192.0.2.1", 443); err == nil {
		t.Fatal("active duplicate accepted")
	}
	a.Close()
	b.Close()
	eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.streams) == 0 })
	if _, err := c.Open(context.Background(), "192.0.2.1", 443); err == nil {
		t.Fatal("closed ID reused")
	}
	allocateErr = errors.New("exhausted shared channel IDs")
	if _, err := c.Open(context.Background(), "192.0.2.1", 443); !errors.Is(err, allocateErr) {
		t.Fatal(err)
	}
}
