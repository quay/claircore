//go:build go1.24

package cache

import (
	"context"
	"runtime"
	"testing"
	"time"
	"weak"
)

// TestLive attempts to test the [Live] cache.
//
// This is inherently probabilistic and dependent on runtime behavior.
func TestLive(t *testing.T) {
	// Attempt to minimize the state of the heap.
	runtime.GC()
	runtime.Gosched()

	// Value is a type that both has a pointer and is bigger than 16 bytes, in
	// an effort to avoid the runtime's allocation batching
	type value struct {
		key uint32
		_   [12]byte
		_   *bool
	}

	var c Live[uint32, value]
	c.Create = func(_ context.Context, key uint32) (*value, error) {
		return &value{key: key}, nil
	}
	ctx := t.Context()
	var wp weak.Pointer[value]

	func() {
		orig, err := c.Get(ctx, 0xF000000F, nil)
		if err != nil {
			t.Fatal(err)
		}

		cached, err := c.Get(ctx, 0xF000000F, nil)
		if err != nil {
			t.Fatal(err)
		}
		wp = weak.Make(cached)

		t.Logf("values: orig: %p, cached: %p", orig, cached)
		if orig != cached {
			t.Fail()
		}
	}()

	// Spin for up to 10 sec.
	ctx, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	var ok bool
	t.Log("spinning on GC")
	for n := 0; !ok; n++ {
		runtime.GC()
		runtime.Gosched()
		ok = true // Assume this worked. Failing checks flip it to false.

		ct := 0
		c.m.Range(func(k, _ any) bool {
			ct++
			return true
		})
		t.Logf("%d: found values in the cache: %d", n, ct)
		t.Logf("%d: weak pointer has value: %p", n, wp.Value())

		nv, err := c.Get(ctx, 0xF000000F, nil)
		if err != nil {
			t.Logf("%d: Get: %v", err, n)
		}
		np := weak.Make(nv)
		t.Logf("%d: weak pointers: prev: %p, new: %p", n, wp.Value(), np.Value())
		ok = ct == 0 && wp.Value() == nil && err == nil && wp != np

		select {
		case <-ctx.Done():
			t.Fatal(context.Cause(ctx))
		default:
		}
	}
}
