package distlock

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

const (
	trySessionLock   = `SELECT lock FROM pg_try_advisory_lock($1) lock WHERE lock = true;`
	trySessionUnlock = `SELECT lock FROM pg_advisory_unlock($1) lock WHERE lock = true;`
)

// Signifies mutual exclusion could not be obtained.
// In other words another process owns a requested lock.
var ErrMutualExclusion = fmt.Errorf("another process is holding the requested lock")

// Signifies the database is unavialable. Locks cannot be provided.
var ErrDatabaseUnavailable = fmt.Errorf("database currently unavailable.")

// ErrContextCanceled indicates the parent's context was canceled or
// the lock's cancelFunc was invoked.
var ErrContextCanceled = fmt.Errorf("ErrContextCanceled")

// ErrMaxLocks informs caller maximum number of locks have been
// taken.
var ErrMaxLocks = fmt.Errorf("maximum number of locks acquired")

func keyify(key string) []byte {
	h := fnv.New64a()
	io.WriteString(h, key)
	b := []byte{}
	return h.Sum(b)
}

type RequestType int

const (
	Invalid RequestType = iota
	Lock
	Unlock
)

// request is an internal request for a lock
type request struct {
	t        RequestType
	key      string
	respChan chan response
}

// response is an internal response for a
// lock request
type response struct {
	// will be true if lock is acquired
	ok  bool
	ctx context.Context
}

// guard provides a concurrency and deadlock safe api for requesting
// distributed locks.
//
// guard should only be created via a Manager's constructor.
type guard struct {
	max          uint64
	counter      uint64
	chanMu       sync.Mutex
	reqChan      chan request
	dsn          string
	locks        map[string]*lctx
	conn         *pgx.Conn
	online       atomic.Value
	reconnecting atomic.Value
}

// ioLoop is a serialized event loop ensuring synchronization of
// internal data structure access.
func (m *guard) ioLoop(ctx context.Context) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "distlock/guard.ioLoop"),
	)
	zlog.Info(ctx).Msg("lock manager online.")
	t := time.NewTicker(30 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// only ping if we are online.
			if m.online.Load().(bool) {
				if err := m.conn.Ping(ctx); err != nil {
					zlog.Info(ctx).Msg("detected database disconnection. entry reconnect loop.")
					m.reconnect(ctx)
				}
			}
		case req := <-m.reqChan:
			m.handleRequest(ctx, req)
		case <-ctx.Done():
			m.quit(ctx)
			return
		}
	}
}

// reconnect occurs when the database connection is lost.
//
// gaurenteed to have exclusive access to internal data structures.
func (m *guard) reconnect(ctx context.Context) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "distlock/guard.reconnect"),
	)
	m.online.Store(false)
	m.reconnecting.Store(true)
	m.counter = 0

	for key, lock := range m.locks {
		lock.cancel(ErrDatabaseUnavailable)
		delete(m.locks, key)
	}

	// this is launched in a go-routine to
	// so ioLoop unblocks.
	go func(ctx context.Context) {
		defer m.reconnecting.Store(false)
		for {
			if ctx.Err() != nil {
				return
			}

			zlog.Info(ctx).Str("timeout", (500*time.Millisecond).String()).
				Str("dsn", m.dsn).
				Msg("attempting database reconnect with timeout")
			tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			conn, err := pgx.Connect(tctx, m.dsn)
			cancel()
			if err != nil {
				continue
			}

			// re-initialize connection
			m.conn = conn

			// re-initialize map
			m.locks = make(map[string]*lctx)

			// set status back to online
			m.online.Store(true)
			zlog.Info(ctx).Str("dsn", m.dsn).Msg("database connection restored")
			return
		}
	}(ctx)
}

// request will provide the caller with the results of a lock request.
//
// request is guaranteed to return a response.
func (m *guard) request(r request) response {
	m.chanMu.Lock()
	defer m.chanMu.Unlock()
	select {
	case m.reqChan <- r:
		// if a request is pushed, a response is guaranteed
		resp := <-r.respChan
		return resp
	default:
		// this will only happen if guard is shutting down
		// and reqChan is nil
		return response{ok: false, ctx: &lctx{done: closedchan, err: ErrContextCanceled}}
	}
}

// quit ensures graceful termination of the guard.
//
// guaranteed to have exclusive access to internal data structures.
func (m *guard) quit(ctx context.Context) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "distlock/guard.quit"),
	)
	zlog.Info(ctx).Msg("graceful quit of lock manager started.")
	for m.reconnecting.Load().(bool) {
		// waiting for reconnect loop to quit.
		// should be a short spin
	}

	// set offline. no new requests will enter the guard
	m.online.Store(false)

	// replace channel with nil causing any in-flight lock requests to fail.
	m.chanMu.Lock()
	rc := m.reqChan
	m.reqChan = nil
	m.chanMu.Unlock()

	// safe to close channel now
	close(rc)

	// drain any requests which made it to the channel before nil swap
	for req := range rc {
		var resp response
		resp.ctx = &lctx{
			done: closedchan,
			err:  ErrContextCanceled,
		}
		resp.ok = false
		req.respChan <- resp
	}

	// cancel all locks
	for key, lock := range m.locks {
		lock.cancel(ErrContextCanceled)
		delete(m.locks, key)
	}

	// if conn is present close it. releases all locks
	if m.conn != nil {
		m.conn.Close(context.Background())
	}
	zlog.Info(ctx).Msg("graceful quit of lock manager succeeded.")
}

// handleRequest multiplexes guard requests to the appropriate postgres
// methods.
//
// guaranteed to have exclusive access to internal data structures.
func (m *guard) handleRequest(ctx context.Context, req request) {
	var resp response

	if !m.online.Load().(bool) {
		resp.ctx = &lctx{
			done: closedchan,
			err:  ErrDatabaseUnavailable,
		}
		resp.ok = false
		req.respChan <- resp
	}

	switch req.t {
	case Lock:
		resp := m.lock(ctx, req.key)
		req.respChan <- resp
	case Unlock:
		resp := m.unlock(ctx, req.key)
		req.respChan <- resp
	default:
	}

	return
}

func (m *guard) lock(ctx context.Context, key string) response {
	if _, ok := m.locks[key]; ok {
		return response{false, &lctx{done: closedchan, err: ErrMutualExclusion}}
	}

	if m.counter >= m.max {
		return response{false, &lctx{done: closedchan, err: ErrMaxLocks}}
	}

	// this looks odd, but allows us to
	// avoid a large amount of allocs.
	// see: https://www.ldelossa.is/blog/posts/allocation_optimization_in_go.post
	rr := m.conn.PgConn().ExecParams(ctx,
		trySessionLock,
		[][]byte{
			keyify(key),
		},
		nil,
		[]int16{1},
		nil)
	tag, err := rr.Close()
	if err != nil {
		return response{false, &lctx{done: closedchan, err: err}}
	}
	if tag.RowsAffected() == 0 {
		return response{false, &lctx{done: closedchan, err: ErrMutualExclusion}}
	}

	lock := &lctx{
		err:  nil,
		done: make(chan struct{}),
	}

	m.locks[key] = lock
	m.counter++
	return response{true, lock}
}

func (m *guard) unlock(ctx context.Context, key string) response {
	var lock *lctx
	var ok bool
	if lock, ok = m.locks[key]; !ok {
		return response{false, &lctx{done: closedchan, err: fmt.Errorf("no lock for key %s", key)}}
	}

	// lock cancelation and counter decrement
	defer func() {
		lock.cancel(ErrContextCanceled)
		delete(m.locks, key)
		m.counter--
	}()

	rr := m.conn.PgConn().ExecParams(ctx,
		trySessionUnlock,
		[][]byte{
			keyify(key),
		},
		nil,
		[]int16{1},
		nil)
	tag, err := rr.Close()
	if err != nil {
		return response{false, &lctx{done: closedchan, err: err}}
	}
	if tag.RowsAffected() == 0 {
		return response{false, &lctx{done: closedchan, err: fmt.Errorf("unlock of key %s returned false", key)}}
	}
	return response{true, nil}
}
