package integration

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
)

var (
	rngMu sync.Mutex
	rng   *rand.Rand
)

func mkIDs() (uint64, uint64) {
	rngMu.Lock()
	defer rngMu.Unlock()
	return rng.Uint64(), rng.Uint64()
}

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
const (
	DefaultDSN      = `host=localhost port=5434 user=claircore dbname=claircore sslmode=disable` // connection string for our local development. see docker-compose.yaml at root
	EnvPGConnString = "POSTGRES_CONNECTION_STRING"
)
const (
	loadUUID        = `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`
	createRole      = `CREATE ROLE %s LOGIN;`
	createDatabase  = `CREATE DATABASE %[2]s WITH OWNER %[1]s ENCODING 'UTF8';`
	killConnections = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`
	dropDatabase    = `DROP DATABASE %s;`
	dropRole        = `DROP ROLE %s;`
)

// NewDB generates a unique database instance for use in concurrent integration tests.
//
// An environment variable maybe use to provide the root connection string used to
// generate a test specific database.
//
// If no environment variable is specified the root connection string defaults to our local
// development db connection string DefaultDSN.
func NewDB(ctx context.Context, t testing.TB) (*DB, error) {
	// if we find an environment variable use this inplace of the passed in DSN.
	// this will mostly be used in CI/CD settings to point to pipeline databases
	var dsn string
	dsnFromEnv := os.Getenv(EnvPGConnString)
	if dsnFromEnv != "" {
		dsn = dsnFromEnv
	} else {
		dsn = DefaultDSN
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)

	dbid, roleid := mkIDs()
	database := fmt.Sprintf("db%x", dbid)
	role := fmt.Sprintf("role%x", roleid)

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

	cfg.ConnConfig.Database = database
	conn, err = pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, loadUUID); err != nil {
		return nil, err
	}
	if err := conn.Close(ctx); err != nil {
		return nil, err
	}

	cfg.ConnConfig.User = role
	t.Logf("config: %+v", struct {
		Host     string
		Port     uint16
		Database string
		User     string
		Password string
	}{
		Host:     cfg.ConnConfig.Host,
		Port:     cfg.ConnConfig.Port,
		Database: cfg.ConnConfig.Database,
		User:     cfg.ConnConfig.User,
		Password: cfg.ConnConfig.Password,
	})
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
