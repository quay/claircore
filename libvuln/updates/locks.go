package updates

import (
	"context"
	"sync"
)

var _ LockSource = (*localLockSource)(nil)

type localLockSource struct {
	sync.Mutex
	wait *sync.Cond
	m    map[string]struct{}
}

// NewLocalLockSource provides locks backed by local concurrency primitives.
func NewLocalLockSource() *localLockSource {
	l := &localLockSource{
		m: make(map[string]struct{}),
	}
	l.wait = sync.NewCond(&l.Mutex)
	return l
}

// BUG(hank) The API provided by localLockSource does not respect the parent
// context cancellation when waiting for a lock.

func (s *localLockSource) Lock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	for _, exists := s.m[key]; exists; _, exists = s.m[key] {
		s.wait.Wait()
	}
	s.m[key] = struct{}{}
	c, f := context.WithCancel(ctx)
	return c, s.cancelfunc(key, f)
}

func (s *localLockSource) TryLock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
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

func (s *localLockSource) Close(ctx context.Context) error {
	return nil
}

// Cancelfunc returns a CancelFunc that calls "next" and then unlocks.
func (s *localLockSource) cancelfunc(key string, next context.CancelFunc) context.CancelFunc {
	return func() {
		next()
		s.Mutex.Lock()
		defer s.Mutex.Unlock()
		delete(s.m, key)
		s.wait.Broadcast()
	}
}

// Peek reports whether the key is locked or not.
func (s *localLockSource) peek(key string) bool {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	_, ok := s.m[key]
	return ok
}
