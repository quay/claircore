package updater

import (
	"context"
	"sync"
)

// LocalLocker provides locks backed by local concurrency primitives.
type localLocker struct {
	sync.Mutex
	wait *sync.Cond
	m    map[string]struct{}
}

var _ Locker = (*localLocker)(nil)

// NewLocalLocker initializes a localLocker.
func newLocalLocker() *localLocker {
	l := &localLocker{
		m: make(map[string]struct{}),
	}
	l.wait = sync.NewCond(&l.Mutex)
	return l
}

// BUG(hank) The localLocker implementation does not respect the parent
// context cancellation when waiting for a lock.

// Lock implements Locker.
func (s *localLocker) Lock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	for _, exists := s.m[key]; exists; _, exists = s.m[key] {
		s.wait.Wait()
	}
	s.m[key] = struct{}{}
	c, f := context.WithCancel(ctx)
	return c, s.cancelfunc(key, f)
}

// TryLock implements Locker.
func (s *localLocker) TryLock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	c, f := context.WithCancel(ctx)
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if _, exists := s.m[key]; exists {
		f()
		return c, f
	}
	s.m[key] = struct{}{}
	return c, s.cancelfunc(key, f)
}

// Cancelfunc returns a CancelFunc that calls "next" and then unlocks.
func (s *localLocker) cancelfunc(key string, next context.CancelFunc) context.CancelFunc {
	return func() {
		next()
		s.Mutex.Lock()
		defer s.Mutex.Unlock()
		delete(s.m, key)
		s.wait.Broadcast()
	}
}
