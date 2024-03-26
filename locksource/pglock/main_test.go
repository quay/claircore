package pglock

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/tracelog"
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
	cfg := db.ConfigV5()
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   testingadapter.NewLogger(t),
		LogLevel: tracelog.LogLevelDebug,
	}

	// Create the Locker.
	l, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	return ctx, l
}
