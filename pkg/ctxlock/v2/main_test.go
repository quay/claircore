package ctxlock

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
)

func basicSetup(t testing.TB) (context.Context, *Locker) {
	t.Helper()
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	// Setup the Database.
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(ctx, t) })
	cfg := db.Config()
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   testingadapter.NewLogger(t),
		LogLevel: tracelog.LogLevelError,
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// Create the Locker.
	l, err := New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(ctx) })

	return ctx, l
}
