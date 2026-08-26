package postgres

import (
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

// liveHeapBytes reports bytes occupied by live (and not-yet-collected) heap
// objects without stopping the world.
func liveHeapBytes(s []metrics.Sample) uint64 {
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func Benchmark_UpdateVulnerabilities(b *testing.B) {
	integration.NeedDB(b)
	// Consider using `-benchtime 1x` when running the 50000, 75000, and 100000.
	for _, sz := range []int{100, 500, 1200, 50000, 75000, 100000} {
		b.Run(strconv.Itoa(sz)+" vulnerabilities", func(b *testing.B) {
			ctx := test.Logging(b)
			pool := pgtest.TestMatcherDB(ctx, b)
			store := NewMatcherStore(pool)
			vulns := genAliasVulns(b.Name(), sz)

			// Sample live heap during the run: B/op reports cumulative
			// allocation and misses how long allocations stay reachable,
			// which is what the chunked alias flush is meant to bound.
			sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
			runtime.GC()
			base := liveHeapBytes(sample)
			var peak atomic.Uint64
			done := make(chan struct{})
			defer close(done)
			go func() {
				tick := time.NewTicker(25 * time.Millisecond)
				defer tick.Stop()
				sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
				for {
					select {
					case <-done:
						return
					case <-tick.C:
						if h := liveHeapBytes(sample); h > peak.Load() {
							peak.Store(h)
						}
					}
				}
			}()

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := store.UpdateVulnerabilities(ctx, b.Name(), driver.Fingerprint(uuid.New().String()), vulns); err != nil {
					b.Fatalf("UpdateVulnerabilities: %v", err)
				}
			}
			b.StopTimer()
			if p := peak.Load(); p > base {
				b.ReportMetric(float64(p-base), "peak-heap-B")
			}
		})
	}
}
