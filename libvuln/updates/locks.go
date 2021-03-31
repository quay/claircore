package updates

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore/pkg/distlock"
	"github.com/quay/claircore/pkg/distlock/postgres"
)

var _ LockSource = (*poolLockSource)(nil)

type poolLockSource struct {
	p   *pgxpool.Pool
	dur time.Duration
}

func (s *poolLockSource) NewLock() distlock.Locker {
	return postgres.NewPool(s.p, s.dur)
}

// PoolLockSource provides locks backed by Postgres advisory locks.
//
// The provided duration is the retry period, as documented in postgres.NewPool.
func PoolLockSource(p *pgxpool.Pool, dur time.Duration) (LockSource, error) {
	return &poolLockSource{
		p: p, dur: dur,
	}, nil
}

var _ LockSource = (*localLockSource)(nil)
var _ distlock.Locker = (*localLockTab)(nil)

type localLockSource struct {
	sync.RWMutex
	m map[string]chan struct{}
}

// LocalLockSource provides locks backed by local concurrency primitives.
func LocalLockSource() LockSource {
	return &localLockSource{
		m: make(map[string]chan struct{}),
	}
}

func (s *localLockSource) NewLock() distlock.Locker {
	return &localLockTab{s: s}
}

func (s *localLockSource) getch(key string) chan struct{} {
	s.RLock()
	ch, ok := s.m[key]
	s.RUnlock()
	if !ok {
		s.Lock()
		defer s.Unlock()
		ch, ok = s.m[key]
		if !ok {
			ch = make(chan struct{}, 1)
			ch <- struct{}{}
			s.m[key] = ch
		}
	}
	return ch
}

type localLockTab struct {
	s  *localLockSource
	ch chan struct{}
}

func (t *localLockTab) Lock(ctx context.Context, key string) error {
	ch := t.s.getch(key)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ch:
		t.ch = ch
		return nil
	}
}

func (t *localLockTab) TryLock(ctx context.Context, key string) (bool, error) {
	ch := t.s.getch(key)
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-ch:
		t.ch = ch
		return true, nil
	default:
		return false, nil
	}
}

var errLocalNotLocked = errors.New("not locked")

func (t *localLockTab) Unlock() error {
	if t.ch == nil {
		return errLocalNotLocked
	}
	t.ch <- struct{}{}
	t.ch = nil
	return nil
}
