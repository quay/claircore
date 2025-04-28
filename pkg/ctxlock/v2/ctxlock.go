// Package ctxlock provides a locking mechanism based on context cancellation.
//
// Contexts derived from a Locker are canceled when the underlying connection to
// the lock provider is gone, or when a parent context is canceled.
//
// This package makes use of "unsafe" to avoid some allocations, but the "safe"
// build tag can be provided to use allocating versions of the functions.
//
// TODO(crozzy): Once pgx v4 is no longer needed, copy code at /v2 path one level up
// and delete /v2 path.
package ctxlock

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
)

// TODO(hank) Specify this algorithm to check its soundness.

// New creates a Locker that will pull connections from the provided pool.
//
// The provided context is only used for logging and initial setup. Close must
// be called to release held resources.
func New(ctx context.Context, p *pgxpool.Pool) (*Locker, error) {
	l := &Locker{
		p:  p,
		rc: sync.NewCond(&sync.Mutex{}),
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(l, func(l *Locker) {
		panic(fmt.Sprintf("%s:%d: db lock pool not closed", file, line))
	})
	go l.run(ctx)
	go l.ping(ctx)

	// Wait until a connection is established or the passed context times out.
	ready := make(chan struct{})
	go func() {
		pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels(tracelabel, `ready`)))
		l.rc.L.Lock()
		defer l.rc.L.Unlock()
		for l.conn == nil && l.gen != -1 {
			l.rc.Wait()
		}
		close(ready)
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		l.Close(ctx)
		return nil, ctx.Err()
	}
	return l, nil
}

// Locker provides context-scoped locks.
type Locker struct {
	// P is the pool we should pull connections from.
	p *pgxpool.Pool

	// Rc is the condition variable and Locker used to control access the fields
	// below.
	rc *sync.Cond
	// Conn is unwrapped connection obtained from the pool.
	conn *pgconn.PgConn
	// Cur tracks current, outstanding locks.
	cur map[string]struct{}
	// Gone is a channel that's set up when the connection is obtained, then
	// strobed when the connection is lost.
	gone chan struct{}
	// Gen tracks which generation of connection is available currently.
	// If the lock's generation is less than this number, the lock is stale.
	// If gen is less than 0, the Locker is shutting down.
	gen int
}

// These are some error values used throughout.
var (
	errExiting    = errors.New("ctxlock: exiting")
	errLockFail   = errors.New("ctxlock: lock acquisition failed")
	errDoubleLock = errors.New("ctxlock: lock already held")
	errConnGone   = errors.New("ctxlock: connection gone")
)

// Run pulls a connection out of the pool and runs the reconnect loop.
func (l *Locker) run(ctx context.Context) {
	ctx = pprof.WithLabels(ctx, pprof.Labels(tracelabel, `run`))
	pprof.SetGoroutineLabels(ctx)
	ctx = zlog.ContextWithValues(ctx, "component", "internal/ctxlock/Locker.run")
	for {
		tctx, done := context.WithTimeout(ctx, 5*time.Second)
		err := l.p.AcquireFunc(tctx, l.reconnect(ctx))
		done()
		switch {
		case errors.Is(err, errExiting):
			zlog.Debug(ctx).
				Msg("ctxlocker exiting")
			return
		case errors.Is(err, nil):
			return
		case errors.Is(err, context.DeadlineExceeded):
			zlog.Info(ctx).
				Err(err).
				Msg("retrying immediately")
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("unexpected error; retrying immediately")
		}
	}
}

// Close spins down background goroutines and frees resources.
func (l *Locker) Close(_ context.Context) (_ error) {
	runtime.SetFinalizer(l, nil)
	l.rc.L.Lock()
	defer l.rc.L.Unlock()
	l.gen = -1
	l.rc.Broadcast()
	return nil
}

// Reconnect is the inner part of the Run method.
//
// It acquires a connection, stashes it in the Locker object, then suspends
// itself until awoken. All other methods should strobe the Cond to wake up this
// loop and check if the connection has died.
func (l *Locker) reconnect(ctx context.Context) func(*pgxpool.Conn) error {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/ctxlock/Locker.reconnect")
	return func(c *pgxpool.Conn) error {
		l.rc.L.Lock()
		defer l.rc.L.Unlock()
		l.conn = c.Conn().PgConn()
		l.gone = make(chan struct{})
		l.cur = make(map[string]struct{}, 100) // Guess at a good capacity.
		l.gen++
		ctx = zlog.ContextWithValues(ctx, "gen", strconv.Itoa(l.gen))
		defer func() {
			close(l.gone)
			l.gone = nil
			l.conn = nil
			l.cur = nil
			zlog.Debug(ctx).Msg("torn down")
		}()
		zlog.Debug(ctx).Msg("set up")
		l.rc.Broadcast()

		for l.gen > 0 {
			ctx, done := context.WithTimeout(ctx, time.Second)
			err := c.Ping(ctx)
			done()
			if err != nil {
				zlog.Warn(ctx).
					Err(err).
					Msg("liveness check failed")
				return err
			}
			l.rc.Wait()
		}
		return errExiting
	}
}

// Ping wakes up the reconnect loop periodically.
func (l *Locker) ping(ctx context.Context) {
	pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels(tracelabel, `ping`)))
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	leave := false
	for !leave {
		<-t.C
		l.rc.L.Lock()
		leave = l.gen < 0
		l.rc.L.Unlock()
		l.rc.Broadcast()
	}
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
func (l *Locker) TryLock(parent context.Context, key string) (context.Context, context.CancelFunc) {
	// zlog.Debug(parent).Str("key", key).Msg("trying lock")
	defer trace.StartRegion(parent, pkgname+".TryLock").End()
	child, done := context.WithCancel(parent)
	w, err := l.try(parent, key, done)
	switch {
	case errors.Is(err, nil):
		return child, w.Unwatch
	case errors.Is(err, errConnGone) ||
		errors.Is(err, errLockFail) ||
		errors.Is(err, errDoubleLock):
		zlog.Debug(parent).
			Err(err).
			Str("key", key).
			Msg("lock failed")
	default:
		zlog.Info(parent).
			Err(err).
			Msg("checking lock liveness")
		l.rc.Broadcast()
	}
	done()
	return child, done
}

// Lock attempts to obtain the named lock until it succeeds or the passed
// Context is canceled.
func (l *Locker) Lock(parent context.Context, key string) (context.Context, context.CancelFunc) {
	// zlog.Debug(parent).Str("key", key).Msg("locking")
	defer trace.StartRegion(parent, pkgname+".Lock").End()
	child, done := context.WithCancel(parent)
	for wait := time.Duration(500 * time.Millisecond); ; backoff(&wait) {
		w, err := l.try(parent, key, done)
		switch {
		case errors.Is(err, nil):
			return child, w.Unwatch
		case errors.Is(err, errConnGone) ||
			errors.Is(err, errLockFail) ||
			errors.Is(err, errDoubleLock):
			zlog.Debug(parent).
				Err(err).
				Str("key", key).
				Msg("lock failed")
		default:
			zlog.Info(parent).
				Err(err).
				Msg("checking lock liveness")
			l.rc.Broadcast()
		}

		t := time.NewTimer(wait)
		select {
		case <-parent.Done():
			t.Stop()
			// Only close the child context in the "fail" return path.
			done()
			return parent, noop
		case <-t.C:
			t.Stop()
		}
	}
}

func noop() {}

// Backoff implements a doubling backoff, capped at 10 seconds.
func backoff(w *time.Duration) {
	const max = 10 * time.Second
	(*w) *= 2
	if *w > max {
		*w = max
	}
}

// Try attempts to take an advisory lock and reports an error if unsuccessful.
// If successful, the returned watcher will be configured to call "cf" and
// release the lock.
func (l *Locker) try(ctx context.Context, key string, cf context.CancelFunc) (*watcher, error) {
	const query = `SELECT lock FROM pg_try_advisory_lock($1) lock WHERE lock = true;`
	kb := keyify(key)
	// Ideally we'd set a profiling label for the key, but labels are not
	// recorded for user profiles.
	trace.Logf(ctx, pkgname+".try", "trying lock for %q (%016x)", key, kb)
	l.rc.L.Lock()
	defer l.rc.L.Unlock()
	var err error
	for l.conn == nil {
		return nil, errConnGone
	}
	if _, ok := l.cur[key]; ok {
		return nil, errDoubleLock
	}

	// If we waited for the lock and the parent context is gone, return.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tag, err := l.conn.ExecParams(ctx, query,
		[][]byte{kb}, nil,
		[]int16{1}, nil).Close()
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, errLockFail
	}
	l.cur[key] = struct{}{}
	w := newWatcher(l.unlock(ctx, key, kb, l.gen, cf))
	go w.Watch(ctx, l.gone)
	return w, nil
}

// Unlock returns a function that unconditionally calls "next" and releases the
// advisory lock if needed.
func (l *Locker) unlock(ctx context.Context, key string, kb []byte, gen int, next context.CancelFunc) context.CancelFunc {
	const query = `SELECT lock FROM pg_advisory_unlock($1) lock WHERE lock = true;`
	return func() {
		defer next()
		l.rc.L.Lock()
		defer l.rc.L.Unlock()

		switch {
		case gen < l.gen:
			// If the connection dropped between acquisition and now, there's
			// nothing to be done: this process doesn't have the lock any more.
			return
		case l.conn == nil || l.gen < 0:
			// If the connection is gone currently or the Close method has been
			// called, we've lost the lock or are about to.
			return
		}

		// If the parent context has been canceled, create a new short-lived
		// one to time-box our query.
		var done context.CancelFunc
		if err := ctx.Err(); err != nil {
			ctx, done = context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
		}

		tag, err := l.conn.ExecParams(ctx, query,
			[][]byte{kb}, nil,
			[]int16{1}, nil).Close()
		if err != nil {
			zlog.Debug(ctx).
				Err(err).
				Msg("error during unlock")
			// Since we're in a different call path now, we need to signal on
			// error here, as well.
			l.rc.Broadcast()
			return
		}
		if _, ok := l.cur[key]; !ok || tag.RowsAffected() == 0 {
			zlog.Error(ctx).
				Str("key", key).
				Msg("lock protocol botch")
		}
		delete(l.cur, key)
	}
}
