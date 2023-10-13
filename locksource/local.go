package locksource

import (
	"context"
	"sync"
)

// Local provides locks backed by local concurrency primitives.
//
// The zero Local is ready for use. A Local must not be copied after use.
type Local struct {
	m sync.Map
}

// Barrier is a more descriptive name for a chan struct{}.
//
// It's used as an execution barrier.
type barrier chan struct{}

// Assert [*Local] implements the interface.
var _ ContextLock = (*Local)(nil)

// Lock implements [ContextLock].
func (l *Local) Lock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	for {
		v, load := l.m.LoadOrStore(key, make(barrier))
		b := v.(barrier)
		if load { // Do not have the lock.
			select {
			case <-b:
				continue
			case <-ctx.Done():
				return ctx, func() {}
			}
		}
		// Have the lock.
		c, f := context.WithCancel(ctx)
		return c, l.cancelfunc(b, key, f)
	}
}

// TryLock implements [ContextLock].
func (l *Local) TryLock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	c, f := context.WithCancel(ctx)
	v, load := l.m.LoadOrStore(key, make(barrier))
	if load {
		f()
		return c, func() {}
	}
	b := v.(barrier)
	return c, l.cancelfunc(b, key, f)
}

// Cancelfunc returns a [context.CancelFunc] that calls "next" and then unlocks.
func (l *Local) cancelfunc(b barrier, key string, next context.CancelFunc) context.CancelFunc {
	return func() {
		next()          // Cancel the child Context.
		l.m.Delete(key) // Remove the barrier.
		close(b)        // Alert any waiting goroutines.
	}
}
