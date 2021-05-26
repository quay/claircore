package distlock

import (
	"context"
	"log"
	"math"
	"time"

	"github.com/jackc/pgx/v4"
)

// Manager provides a client facing api for obtaining and returning
// distributed locks.
//
// Manager must not be copied after construction.
type Manager struct {
	pool *reqPool
	// Guard provides a concurrency safe request/response api with
	// guarentees against deadlocks and races.
	g *guard
}

type Opt func(*Manager)

// WithMax sets a maximum limit on the number of
// distributed locks issued at once.
func WithMax(max uint64) Opt {
	return func(m *Manager) {
		m.g.max = max
	}
}

func NewManager(ctx context.Context, dsn string, opts ...Opt) (*Manager, error) {
	reqChan := make(chan request, 1024)
	locks := make(map[string]*lctx)

	conf, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	conn, err := pgx.ConnectConfig(ctx, conf)
	if err != nil {
		return nil, err
	}

	g := &guard{
		reqChan: reqChan,
		dsn:     dsn,
		locks:   locks,
		conn:    conn,
	}
	mgr := &Manager{
		g:    g,
		pool: NewReqPool(50),
	}

	for _, f := range opts {
		f(mgr)
	}

	if mgr.g.max == 0 {
		mgr.g.max = math.MaxUint64
	}

	g.online.Store(true)
	g.reconnecting.Store(false)
	go g.ioLoop(ctx)

	return mgr, nil
}

// TryLock will attempt a lock acquisition.
//
// Regardless of success or failure a context.Context is returned and it's
// error must be checked.
//
// If the incoming context was canceled or the database is not available an ErrContextCanceled
// or ErrDatabaseUnavailable error will be returned, respectively.
//
// If a lock for the incoming key is held by another process an ErrMutualExclusion error will be
// returned.
//
// If the method call successfully acquired a lock the returned context's Err() method will return
// nil and the caller is free to branch off this context further.
func (m *Manager) TryLock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	// parent context already done
	if err := ctx.Err(); err != nil {
		return &lctx{done: closedchan, err: ErrContextCanceled}, func() {}
	}

	// manager is not connected to database
	if !m.g.online.Load().(bool) {
		return &lctx{done: closedchan, err: ErrDatabaseUnavailable}, func() {}
	}

	req := m.pool.Get()
	req.t, req.key = Lock, key

	resp := m.g.request(req)
	m.pool.Put(req)

	// lock was not acquired, error will be in resp.ctx
	if !resp.ok {
		return resp.ctx, func() {}
	}

	m.propagateCancel(ctx, resp.ctx, key)

	return resp.ctx, func() {
		m.unlock(key)
	}
}

// propagateCancel chains the parent context's lifespan to the child's, ensuring
// that when the parent is canceled the child is as well.
func (m *Manager) propagateCancel(parent context.Context, child context.Context, key string) {
	// parent already done.
	if err := parent.Err(); err != nil {
		m.unlock(key)
		return
	}

	// kick off listener. will exit when parent is canceled or child's cancel func is called.
	go func() {
		select {
		case <-parent.Done():
			m.unlock(key)
		case <-child.Done():
		}
	}()
}

// Lock is similar to TryLock but will block on lock acquisition until successful,
// the incoming context is canceled, or the database becomes unavailable.
func (m *Manager) Lock(ctx context.Context, key string) (context.Context, context.CancelFunc) {
	for {
		if ctx.Err() != nil {
			return &lctx{done: closedchan, err: ctx.Err()}, func() {}
		}

		if !m.g.online.Load().(bool) {
			return &lctx{done: closedchan, err: ErrDatabaseUnavailable}, func() {}
		}

		req := m.pool.Get()
		req.t, req.key = Lock, key

		resp := m.g.request(req)
		m.pool.Put(req)

		// lock acquired
		if resp.ok {
			m.propagateCancel(ctx, resp.ctx, key)
			return resp.ctx, func() { m.unlock(key) }
		}

		// if ErrMutualExclusion retry...
		if resp.ctx.Err() == ErrMutualExclusion {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		// received a non mutual exclusion error
		return resp.ctx, func() {}
	}
}

// unlock will issue a request to the guard to unlock a given key.
func (m *Manager) unlock(key string) {
	if !m.g.online.Load().(bool) {
		return
	}

	req := m.pool.Get()
	req.t, req.key = Unlock, key

	resp := m.g.request(req)
	m.pool.Put(req)

	if !resp.ok {
		log.Printf("unlock err: %v", resp.ctx.Err())
	}
}
