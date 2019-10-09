package postgres

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/quay/claircore/test/integration"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib" // needed for sqlx.Open
	"github.com/jmoiron/sqlx"
)

func TestStore(ctx context.Context, t testing.TB) (*sqlx.DB, *Store, func()) {
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/quay/claircore/internal/vulnstore/postgres")
	o, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	o = bytes.TrimSpace(o)

	db, err := integration.NewDB(ctx, t, integration.DefaultDSN, filepath.Join(string(o), "bootstrap.sql"))
	if err != nil {
		t.Fatalf("unable to create test database: %w", err)
	}
	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// setup sqlx
	sx, err := sqlx.Open("pgx", fmt.Sprintf("host=%s port=%d database=%s user=%s",
		cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database, cfg.ConnConfig.User))
	if err != nil {
		t.Fatalf("failed to sqlx Open: %v", err)
	}

	s := NewVulnStore(sx, pool)

	return sx, s, func() {
		db.Close(ctx, t)
	}
}
