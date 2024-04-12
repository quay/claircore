// Package locksource describes the interface that claircore components expect
// to use for locks.
//
// Locks must be consistent system-wide to provide any benefit. That is, if an
// application using the claircore module expects to have multiple instances
// concurrently, any [ContextLock] implementations must be backed by some shared
// resource.
package locksource

import (
	"context"
)

// ContextLock abstracts over how locks are implemented.
//
// The Lock and TryLock methods take an exclusive lock based on the provided and
// return a Context that is canceled if the parent Context is canceled or the
// lock is lost for some other reason.
//
// An online system needs distributed locks.
// Offline use cases can use process-local locks, such as [Local].
type ContextLock interface {
	// Lock waits to acquire the named lock. The returned Context may be
	// canceled if the process loses confidence that the lock is valid.
	Lock(ctx context.Context, key string) (context.Context, context.CancelFunc)
	// TryLock returns a canceled Context if it would need to wait to acquire
	// the named lock.
	TryLock(ctx context.Context, key string) (context.Context, context.CancelFunc)
}
