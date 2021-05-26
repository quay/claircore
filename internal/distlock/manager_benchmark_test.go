package distlock

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func BenchmarkLockUsage(b *testing.B) {
	startDB(b)
	waitDB(b)

	// create a manager
	mCtx, mCancel := context.WithCancel(context.Background())
	defer mCancel()
	manager, err := NewManager(mCtx, dsn)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uuid := uuid.New().String()
		ctx, cancel := manager.TryLock(context.Background(), uuid)
		if err := ctx.Err(); err != nil {
			b.Fatal(err)
		}
		cancel()
	}

}
