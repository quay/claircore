package postgres

import (
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func sampleValue(s []metrics.Sample) uint64 {
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func BenchmarkUpdateVulnerabilities(b *testing.B) {
	integration.NeedDB(b)
	// Consider using `-benchtime 1x` when running the 50000, 75000, and 100000.
	for _, sz := range []int{100, 500, 1200, 50000, 75000, 100000} {
		b.Run(strconv.Itoa(sz)+"Vulnerabilities", func(b *testing.B) {
			ctx := test.Logging(b)
			pool := pgtest.TestMatcherDB(ctx, b)
			store := NewMatcherStore(pool)
			vulns := genAliasVulns(b.Name(), sz)

			// Sample live heap during the run: B/op reports cumulative
			// allocation and misses how long allocations stay reachable,
			// which is what the chunked alias flush is meant to bound.
			runtime.GC()
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				// Record the (lagging) size of the live heap with this metric.
				sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
				base := sampleValue(sample)
				var peak uint64
				tick := time.NewTicker(25 * time.Millisecond)
				defer tick.Stop()
			Tick:
				for {
					select {
					case <-done:
						break Tick
					case <-tick.C:
						peak = max(peak, sampleValue(sample))
					}
				}
				runtime.GC()
				peak = max(peak, sampleValue(sample))
				b.ReportMetric(float64(peak-base), "heapGrowth-B")
			})

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := store.UpdateVulnerabilities(ctx, b.Name(), driver.Fingerprint(uuid.New().String()), vulns); err != nil {
					b.Fatalf("UpdateVulnerabilities: %v", err)
				}
			}
			b.StopTimer()
			close(done)
			wg.Wait()
		})
	}
}
