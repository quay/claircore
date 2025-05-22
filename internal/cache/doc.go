// Package cache provides caching implementations for Go values.
package cache

import "context"

// CreateFunc is the function type used to produce new values to cache.
type CreateFunc[K comparable, V any] func(context.Context, K) (*V, error)
