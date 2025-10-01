// Package ctxlock is deprecated. Use ctxlock/v2 instead.
package ctxlock

import (
	"context"
	"errors"
)

var errDeprecated = errors.New("ctxlock/v1 is deprecated; use ctxlock/v2 instead")

// TODO(hank) Specify this algorithm to check its soundness.

// New creates a Locker that will pull connections from the provided pool.
//
// The provided context is only used for logging and initial setup. Close must
// be called to release held resources.
//
// Deprecated: Use ctxlock/v2 instead.
func New(ctx context.Context, p any) (*Locker, error) {
	return nil, errDeprecated
}

// Locker provides context-scoped locks.
//
// Deprecated: Use ctxlock/v2 instead.
type Locker struct{}

// Close spins down background goroutines and frees resources.
//
// Deprecated: Use ctxlock/v2 instead.
func (l *Locker) Close(_ context.Context) (_ error) {
	return errDeprecated
}

/*
The TryLock and Lock methods do not add logging baggage, because the additional
allocations around the context.Context really stack up. Ensure that any
additional information is added to the zlog calls directly.

I've left some Debug logs commented out because zlog needs to gain a level knob
for tests. Currently, the logs always happen and throw off benchmarks.
*/

// TryLock attempts to lock on the provided key.
//
// If unsuccessful, an already-canceled Context will be returned.
//
// If successful, the returned Context will be parented to the passed-in Context
// and also to the underlying connection used for the lock.
//
// Deprecated: Use ctxlock/v2 instead.
func (l *Locker) TryLock(parent context.Context, key string) (context.Context, context.CancelFunc) {
	return nil, nil
}

// Lock attempts to obtain the named lock until it succeeds or the passed
// Context is canceled.
//
// Deprecated: Use ctxlock/v2 instead.
func (l *Locker) Lock(parent context.Context, key string) (context.Context, context.CancelFunc) {
	return nil, nil
}
