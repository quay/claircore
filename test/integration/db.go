package integration

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
)

var rng *rand.Rand

func init() {
	// Seed our rng.
	b := make([]byte, 8)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		panic(err)
	}
	seed := rand.NewSource(int64(binary.BigEndian.Uint64(b)))
	rng = rand.New(seed)
}

// DefaultDSN is a dsn for database server usually set up by the project's
// Makefile.
const DefaultDSN = `host=localhost port=5434 user=claircore dbname=claircore sslmode=disable`

const (
	createRole      = `CREATE ROLE %s LOGIN;`
	createDatabase  = `CREATE DATABASE %[2]s WITH OWNER %[1]s ENCODING 'UTF8';`
	killConnections = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`
	dropDatabase    = `DROP DATABASE %s;`
	dropRole        = `DROP ROLE %s;`
)

// NewDB creates a new database and populates it with the contents of initfile.
func NewDB(ctx context.Context, t testing.TB, dsn, initfile string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)

	database := fmt.Sprintf("db%x", rng.Uint64())
	role := fmt.Sprintf("role%x", rng.Uint64())

	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf(createRole, role)); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf(createDatabase, role, database)); err != nil {
		return nil, err
	}
	if err := conn.Close(ctx); err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(initfile)
	if err != nil {
		return nil, err
	}

	cfg.ConnConfig.Database = database
	cfg.ConnConfig.User = role
	conn, err = pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Exec(ctx, bytes.NewBuffer(b).String()); err != nil {
		return nil, err
	}
	if err := conn.Close(ctx); err != nil {
		return nil, err
	}
	t.Logf("config: %+#v", cfg.ConnConfig)
	cfg.ConnConfig.Logger = nil

	return &DB{
		dsn: dsn,
		cfg: cfg,
	}, nil
}

// DB is a handle for connecting to an cleaning up a created database.
type DB struct {
	dsn string
	cfg *pgxpool.Config
}

// Config returns a pgxpool.Config for the created database.
func (db *DB) Config() *pgxpool.Config {
	return db.cfg
}

// Close tears down the created database.
func (db *DB) Close(ctx context.Context, t testing.TB) {
	cfg, err := pgxpool.ParseConfig(db.dsn)
	if err != nil {
		panic(err) // Should never happen.
	}
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, killConnections, db.cfg.ConnConfig.Database); err != nil {
		t.Error(err)
	}

	if _, err := conn.Exec(ctx, fmt.Sprintf(dropDatabase, db.cfg.ConnConfig.Database)); err != nil {
		t.Error(err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf(dropRole, db.cfg.ConnConfig.User)); err != nil {
		t.Error(err)
	}
	db.cfg = nil
}
