package updates

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLocalLockUnlock(t *testing.T) {
	ctx := context.Background()
	locks := LocalLockSource()

	l := locks.NewLock()

	t.Log("lock")
	if err := l.Lock(ctx, t.Name()); err != nil {
		t.Error(err)
	}
	t.Log("unlock")
	if err := l.Unlock(); err != nil {
		t.Error(err)
	}

	t.Log("lock")
	if err := l.Lock(ctx, t.Name()); err != nil {
		t.Error(err)
	}
	t.Log("unlock")
	if err := l.Unlock(); err != nil {
		t.Error(err)
	}
}

func TestLocalTryLock(t *testing.T) {
	ctx := context.Background()
	locks := LocalLockSource()
	locked := make(chan struct{})
	unlock := make(chan struct{})
	unlocked := make(chan struct{})
	go func() {
		l := locks.NewLock()
		if err := l.Lock(ctx, t.Name()); err != nil {
			t.Error(err)
		}
		defer func() {
			if err := l.Unlock(); err != nil {
				t.Error(err)
			}
			close(unlocked)
			t.Log("lock released")
		}()
		t.Log("lock held")
		close(locked)
		<-unlock
	}()

	<-locked
	l := locks.NewLock()
	ok, err := l.TryLock(ctx, t.Name())
	if err != nil {
		t.Error(err)
	}
	t.Logf("try: %v", ok)
	if ok {
		t.Error("wanted TryLock to fail")
	}
	close(unlock)
	<-unlocked
	ok, err = l.TryLock(ctx, t.Name())
	if err != nil {
		t.Error(err)
	}
	t.Logf("try: %v", ok)
	if !ok {
		t.Error("wanted TryLock to succeed")
	}
	if err := l.Unlock(); err != nil {
		t.Error(err)
	}
	t.Log("unlocked")
}

func TestLocalLockSequential(t *testing.T) {
	ctx := context.Background()
	locks := LocalLockSource()
	var wg sync.WaitGroup
	wg.Add(2)
	var ct uint64
	l1 := locks.NewLock()
	l2 := locks.NewLock()
	if err := l1.Lock(ctx, t.Name()); err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := l2.Lock(ctx, t.Name()); err != nil {
			t.Error(err)
		}
		defer func() {
			if err := l2.Unlock(); err != nil {
				t.Error(err)
			}
			wg.Done()
		}()
		t.Log("1 → 2")
		if !atomic.CompareAndSwapUint64(&ct, 1, 2) {
			t.Error("ordering error")
		}
	}()
	go func() {
		defer func() {
			if err := l1.Unlock(); err != nil {
				t.Error(err)
			}
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
