package ctxlock

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

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
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
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
