package ctxlock

import (
	"context"
	"runtime/pprof"
	"sync"
)

// A Watcher waits on two cancellation sources and makes sure to call the
// wrapped function as soon as possible.
//
// The wrapped function is called exactly once.
type watcher struct {
	once     sync.Once
	onCancel func()
	done     chan struct{}
}

func newWatcher(onCancel func()) *watcher {
	w := &watcher{
		onCancel: onCancel,
		done:     make(chan struct{}),
	}
	// Capture the call to Lock or TryLock.
	profile.Add(w, 3)
	return w
}

// Watch on the provided channel.
//
// This function should be called as a new goroutine.
// The provided context is used only for setting pprof labels.
func (w *watcher) Watch(ctx context.Context, ch <-chan struct{}) {
	if ch == nil {
		panic("nil channel")
	}
	pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels(tracelabel, `watch`)))

	select {
	case <-ch:
		w.once.Do(w.onCancel)
		<-w.done
	case <-w.done:
	}
}

// Unwatch tears down the watch. It should be called unconditionally.
func (w *watcher) Unwatch() {
	w.once.Do(w.onCancel)
	close(w.done)
	profile.Remove(w)
}
