//go:build go1.24

package cache

import (
	"context"
	"runtime"
	"sync"
	"unique"
	"weak"

	"github.com/quay/claircore/internal/singleflight"
)

// Live is a cache that keeps a cached copy as long as the go runtime determines
// the value is live.
//
// See also: [weak.Pointer].
type Live[K comparable, V any] struct {
	create func(context.Context, K) (*V, error)
	m      sync.Map
	sf     singleflight.Group[K, *V]
}

// NewLive creates a cache that relies on the runtime's liveness judgment.
//
// If the "create" function needs a complex type to be able to construct a
// value, consider using [unique.Handle] to be able to satisfy the "comparable"
// constraint.
func NewLive[K comparable, V any](create func(context.Context, K) (*V, error)) *Live[K, V] {
	return &Live[K, V]{create: create}
}

var _ unique.Handle[string] // for docs

// Get returns a pointer to the value associated with the key, calling the
// "create" function that was passed to [NewLive] as needed to construct values.
func (c *Live[K, V]) Get(ctx context.Context, key K) (*V, error) {
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
				v, err := c.create(ctx, key)
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
