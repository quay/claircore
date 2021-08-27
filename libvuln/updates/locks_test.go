package updates

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLocalLockUnlock(t *testing.T) {
	ctx := context.Background()
	l := NewLocalLockSource()

	t.Log("lock")
	c, done := l.Lock(ctx, t.Name())
	if err := c.Err(); err != nil {
		t.Error(err)
	}
	t.Log("unlock")
	done()
	if l.peek(t.Name()) {
		t.Error("lock held")
	}

	t.Log("lock")
	c, done = l.Lock(ctx, t.Name())
	if err := c.Err(); err != nil {
		t.Error(err)
	}
	t.Log("unlock")
	done()
	if l.peek(t.Name()) {
		t.Error("lock held")
	}
}

func TestLocalTryLock(t *testing.T) {
	ctx := context.Background()
	locks := NewLocalLockSource()
	locked := make(chan struct{})
	unlock := make(chan struct{})
	unlocked := make(chan struct{})
	go func() {
		ctx, done := locks.Lock(ctx, t.Name())
		if err := ctx.Err(); err != nil {
			t.Error(err)
		}
		defer func() {
			done()
			close(unlocked)
			t.Log("lock released")
		}()
		t.Log("lock held")
		close(locked)
		<-unlock
	}()

	<-locked
	lc, done := locks.TryLock(ctx, t.Name())
	t.Logf("try: %v", lc.Err())
	if !errors.Is(lc.Err(), context.Canceled) {
		t.Error("wanted TryLock to fail")
	}
	done()
	close(unlock)
	<-unlocked
	lc, done = locks.TryLock(ctx, t.Name())
	t.Logf("try: %v", lc.Err())
	if !errors.Is(lc.Err(), nil) {
		t.Error("wanted TryLock to succeed")
	}
	done()
	t.Log("unlocked")
}

func TestLocalLockSequential(t *testing.T) {
	ctx := context.Background()
	locks := NewLocalLockSource()
	var wg sync.WaitGroup
	wg.Add(2)
	var ct uint64
	_, d1 := locks.Lock(ctx, t.Name())
	go func() {
		_, d2 := locks.Lock(ctx, t.Name())
		defer func() {
			d2()
			wg.Done()
		}()
		t.Log("1 → 2")
		if !atomic.CompareAndSwapUint64(&ct, 1, 2) {
			t.Error("ordering error")
		}
	}()
	go func() {
		defer func() {
			d1()
			wg.Done()
		}()
		t.Log("0 → 1")
		if !atomic.CompareAndSwapUint64(&ct, 0, 1) {
			t.Error("ordering error")
		}
	}()

	wg.Wait()
	if got, want := ct, uint64(2); got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}
