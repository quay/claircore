package updates

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLocal(t *testing.T) {
	locks := NewLocalLockSource()

	t.Run("LockUnlock", func(t *testing.T) {
		ctx := t.Context()
		key := t.Name()

		for range 2 {
			t.Log("lock")
			c, done := locks.Lock(ctx, key)
			if err := c.Err(); err != nil {
				t.Error(err)
			}
			t.Log("unlock")
			done()
			if locks.peek(key) {
				t.Error("lock held")
			}
		}
	})

	t.Run("TryLock", func(t *testing.T) {
		var wg sync.WaitGroup
		ctx := t.Context()
		key := t.Name()

		doStart := make(chan struct{})
		held := make(chan struct{})
		doRelease := make(chan struct{})
		released := make(chan struct{})
		wg.Add(3)

		// Initial lock.
		go func() {
			defer wg.Done()
			<-doStart

			ctx, done := locks.Lock(ctx, key)
			if err := ctx.Err(); err != nil {
				t.Error(err)
				return
			}
			t.Log("lock held")
			close(held)
			<-doRelease
			done()
			close(released)
			t.Log("lock released")
		}()

		// Attempt to lock while the first goroutine holds it.
		go func() {
			defer wg.Done()
			<-doStart

			<-held
			lc, done := locks.TryLock(ctx, key)
			t.Logf("try: %v", lc.Err())
			if !errors.Is(lc.Err(), context.Canceled) {
				t.Error("wanted TryLock to fail")
			}
			done()
			close(doRelease)
		}()

		// Attempt to lock after the first goroutine releases it.
		go func() {
			defer wg.Done()
			<-doStart

			<-released
			lc, done := locks.TryLock(ctx, key)
			t.Logf("try: %v", lc.Err())
			if !errors.Is(lc.Err(), nil) {
				t.Error("wanted TryLock to succeed")
			}
			done()
			t.Log("lock released")
		}()

		close(doStart)
		wg.Wait()
	})

	t.Run("LockSequential", func(t *testing.T) {
		var wg sync.WaitGroup
		ctx := t.Context()
		key := t.Name()

		wg.Add(2)
		var ct uint64

		// Take the lock first.
		_, d1 := locks.Lock(ctx, key)

		// Spawn the second writer.
		go func() {
			// This should block.
			_, d2 := locks.Lock(ctx, key)
			t.Log("1 → 2")
			if !atomic.CompareAndSwapUint64(&ct, 1, 2) {
				t.Error("ordering error")
			}
			d2()
			wg.Done()
		}()

		// Spawn the first writer
		go func() {
			t.Log("0 → 1")
			if !atomic.CompareAndSwapUint64(&ct, 0, 1) {
				t.Error("ordering error")
			}
			d1()
			wg.Done()
		}()

		wg.Wait()
		if got, want := ct, uint64(2); got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
	})
}
