package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

// NewPool returns a lock struct backed by the provided connection pool.
//
// The returned lock can be reused
func NewPool(pool *pgxpool.Pool, retry time.Duration) *Pool {
	return &Pool{
		pool:  pool,
		retry: retry,
	}
}

// Pool implements a distlock.Locker backed by a pgxpool.Pool.
type Pool struct {
	pool  *pgxpool.Pool
	retry time.Duration

	mu     sync.Mutex
	held   bool
	ctx    context.Context
	cancel func()
	tx     pgx.Tx
}

// TryLock is a nonblocking attempt at taking the lock identified by 'key'.
//
// If successful, the duration of the lock is tied to the provided context; that
// is, if the context is canceled the lock will automatically be released.
func (p *Pool) TryLock(ctx context.Context, key string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.held {
		// If another caller has beat us here, report failure.
		// If this reported true here, this would effectively act like a
		// recursive lock.
		return false, nil
	}
	k := crushkey(key)

	done := make(chan struct{})
	defer close(done)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			// If the passed-in context is cancelled before we succeed taking
			// the lock, propagate the cancellation.
			p.cancel()
		}
	}()

	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		return false, err
	}

	var ok bool
	r := tx.QueryRow(p.ctx, manifestAdvisoryLock, k)
	if err := r.Scan(&ok); err != nil || !ok {
		tx.Rollback(p.ctx)
		if err != nil {
			return false, err
		}
		return false, nil
	}

	p.held = true
	p.tx = tx
	return true, nil
}

// Lock attempts to take the lock identified by 'key', blocking and retrying on
// the period specified at creation until successful or the provided context is
// cancelled.
func (p *Pool) Lock(ctx context.Context, key string) error {
	// Unroll once through the loop to make sure we try asap.
	ok, err := p.TryLock(ctx, key)
	if err != nil {
		return fmt.Errorf("failed at attempting initial lock acquisition: %v", err)
	}
	if ok {
		return nil
	}

	t := time.NewTicker(p.retry)
	defer t.Stop()
	for !ok {
		select {
		case <-t.C:
			ok, err = p.TryLock(ctx, key)
		case <-ctx.Done():
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("failed at attempting lock acquisition: %v", err)
		}
	}
	return nil
}

// Unlock releases a held lock and resets the lock for future use.
func (p *Pool) Unlock() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.held {
		return fmt.Errorf("attempted to unlock when no lock has been acquired")
	}
	if p.tx == nil {
		return fmt.Errorf("lock in invalid state")
	}

	if err := p.tx.Commit(p.ctx); err != nil {
		return fmt.Errorf("failed to commit transaction and free lock: %v", err)
	}
	p.cancel()
	p.held = false
	p.tx = nil
	p.ctx = nil
	p.cancel = nil
	return nil
}
