package ctxlock

import (
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/zlog"
)

func TestUncontested(t *testing.T) {
	ctx, l := basicSetup(t)
	const (
		w  = 4
		ct = 100
	)

	ids := make([]string, w*ct)
	for i := range ids {
		ids[i] = uuid.New().String()
	}
	wi := make([][]string, w)
	for i := range wi {
		off := i * ct
		wi[i] = ids[off : off+ct]
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(wi))
	for i := range wi {
		go func(i int) {
			defer wg.Done()
			ctx := zlog.ContextWithValues(ctx, "worker", strconv.Itoa(i))
			<-start
			t.Logf("worker %d: start", i)
			for _, id := range wi[i] {
				lc, done := l.TryLock(ctx, id)
				if err := lc.Err(); err != nil {
					t.Error(err)
				}
				done()
			}
			t.Logf("worker %d: locked %d keys", i, len(wi[i]))
		}(i)
	}

	close(start)
	wg.Wait()
}

func TestContested(t *testing.T) {
	ctx, l := basicSetup(t)
	const (
		w  = 4
		ct = 100
	)

	ids := make([]string, ct)
	for i := range ids {
		ids[i] = uuid.New().String()
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(w)
	for i := 0; i < w; i++ {
		go func(i int) {
			defer wg.Done()
			ctx := zlog.ContextWithValues(ctx, "worker", strconv.Itoa(i))
			<-start
			t.Logf("worker %d: start", i)
			for _, id := range ids {
				lc, done := l.Lock(ctx, id)
				if err := lc.Err(); err != nil {
					t.Errorf("worker %d: key %q: %v", i, id, err)
				}
				done()
			}
			t.Logf("worker %d: locked %d keys", i, len(ids))
		}(i)
	}

	close(start)
	wg.Wait()
}
