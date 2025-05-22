//go:build go1.24

package cache

import (
	"context"
	"encoding/binary"
	"runtime"
	"testing"
	"weak"
)

func TestLive(t *testing.T) {
	var c Live[uint32, [4]byte]
	c.Create = func(_ context.Context, key uint32) (*[4]byte, error) {
		var v [4]byte
		binary.LittleEndian.PutUint32(v[:], key)
		return &v, nil
	}
	ctx := t.Context()

	a, err := c.Get(ctx, 0xF000000F, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := c.Get(ctx, 0xF000000F, nil)
	if err != nil {
		t.Fatal(err)
	}
	wp := weak.Make(b)

	t.Logf("a: %p, b: %p", a, b)
	if a != b {
		t.Fail()
	}
	a, b = nil, nil

	for range 2 { // Need two cycles:
		runtime.GC()
	}

	found := false
	c.m.Range(func(k, _ any) bool {
		found = true
		t.Logf("found: %v", k)
		return true
	})
	if found {
		t.Error("found values in the cache")
	}
	if wp.Value() != nil {
		t.Error("weak pointer still has value")
	}

	n, err := c.Get(ctx, 0xF000000F, nil)
	if err != nil {
		t.Fatal(err)
	}
	if np := weak.Make(n); wp == np {
		t.Error("expected different weak pointer values")
	}
}
