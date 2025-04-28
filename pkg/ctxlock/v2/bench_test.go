package ctxlock

import (
	"testing"

	"github.com/google/uuid"
)

func BenchmarkUncontended(b *testing.B) {
	ctx, l := basicSetup(b)

	// Generate all the keys.
	ids := make([]string, b.N)
	for i := range ids {
		ids[i] = uuid.New().String()
	}

	// Reset the benchmarking and measure just the locking.
	b.ResetTimer()
	b.ReportAllocs()
	for _, key := range ids {
		ctx, done := l.TryLock(ctx, key)
		if err := ctx.Err(); err != nil {
			b.Error(err)
		}
		done()
	}
}
