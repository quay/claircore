// +build integration

package postgres

import (
	"context"
	"log"
	"testing"
	"time"
)

func Test_ScanLock_Concurrent(t *testing.T) {
	var tt = []struct {
		// the name of this test
		name string
		// the hash used to test the lock
		hash string
		// test timeout in defense of deadlock
		timeout time.Duration
		// the number of concurrent scans
		count int
	}{
		{
			name:    "two concurrent scans",
			hash:    "test-manifest-hash",
			timeout: 20 * time.Second,
			count:   2,
		},
		{
			name:    "three concurrent scans",
			hash:    "test-manifest-hash",
			timeout: 20 * time.Second,
			count:   3,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			db, _, teardown := NewTestStore(t)
			defer teardown()

			ctx, cancel := context.WithTimeout(context.Background(), table.timeout)
			defer cancel()

			done := make(chan int, table.count)
			for i := 0; i < table.count; i++ {
				worker := i
				go func(worker int) {
					sl := NewScanLock(db, 1*time.Second)

					err := sl.Lock(ctx, table.hash)
					if err != nil {
						log.Printf("worker %d lock acquire failed: %v", worker, err)
					}
					log.Printf("worker %d acquired lock", worker)

					log.Printf("worker %d sleeping...", worker)
					time.Sleep(5 * time.Second)

					err = sl.Unlock()
					if err != nil {
						log.Printf("worker %d unlock failed: %v", worker, err)
					}
					log.Printf("worker %d unlocked lock", worker)

					// send done signal
					done <- worker
				}(worker)
			}

			var tokens int
			for {
				select {
				case w := <-done:
					log.Printf("worker %d finished", w)
					tokens++
				case <-ctx.Done():
					t.Fatalf("context timed out before all workers finished")
				default:
					if tokens == table.count {
						return
					}
				}
			}
		})
	}
}
