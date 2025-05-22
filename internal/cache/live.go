//go:build go1.24

package cache

import (
	"context"
	"runtime"
	"sync"
	"weak"

	"github.com/quay/claircore/internal/singleflight"
)

// Live is a cache that keeps a cached copy as long as the go runtime determines
// the value is live.
//
// The Create member can be populated to simplify a call site, ala
// [sync.Pool.New].
// The zero value is safe to use.
//
// See also: [weak.Pointer].
type Live[K comparable, V any] struct {
	Create CreateFunc[K, V]
	m      sync.Map
	sf     singleflight.Group[K, *V]
}

// Get returns a pointer to the value associated with the key, calling the
// "Create" function if populated and the "create" argument is nil.
//
// This function will panic if neither function is provided.
func (c *Live[K, V]) Get(ctx context.Context, key K, create CreateFunc[K, V]) (*V, error) {
	var fn CreateFunc[K, V]
	switch {
	case create != nil:
		fn = create
	case c.Create != nil:
		fn = c.Create
	default:
		panic("programmer error: missing create function")
	}
	for {
		// Try to load an existing value out of the cache.
		value, ok := c.m.Load(key)
		if !ok {
			// No value found. Create a new value.
			fn := func() (*V, error) {
				// Eagerly check the Context so that every create function
				// doesn't need the preamble.
				//
				// Do this because this goroutine may have gone around the loop
				// multiple times and found entries in the map that had
				// invalidated weak pointers, so the context may have expired.
				if ctx.Err() != nil {
					return nil, context.Cause(ctx)
				}
				v, err := fn(ctx, key)
				if err != nil {
					return nil, err
				}

				wp := weak.Make(v)
				c.m.Store(key, wp)
				runtime.AddCleanup(v, func(key K) {
					// Only delete if the weak pointer is equal. If it's not,
					// someone else already deleted the entry and installed a
					// new pointer.
					c.m.CompareAndDelete(key, wp)
				}, key)
				return v, nil
			}

			ch := c.sf.DoChan(key, fn)
			select {
			case res := <-ch:
				return res.Val, res.Err
			case <-ctx.Done():
				c.sf.Forget(key)
				return nil, context.Cause(ctx)
			}
		}

		// See if our cache entry is valid.
		if v := value.(weak.Pointer[V]).Value(); v != nil {
			return v, nil
		}
		// Discovered a nil entry awaiting cleanup. Eagerly delete it.
		c.m.CompareAndDelete(key, value)
	}
}

// Clear removes all cached entries.
//
// No additional calls are made for individual values; the cache simply drops
// any references it has.
func (c *Live[K, V]) Clear() { c.m.Clear() }
