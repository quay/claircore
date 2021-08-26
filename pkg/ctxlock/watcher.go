package ctxlock

import "sync"

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
	return &watcher{
		onCancel: onCancel,
		done:     make(chan struct{}),
	}
}

// Watch on the provided channel.
func (w *watcher) Watch(ch <-chan struct{}) {
	if ch == nil {
		panic("nil channel")
	}

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
}
