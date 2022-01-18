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

	up        sync.Once
	pkgDB     *Engine
	pkgConfig *pgxpool.Config
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

const (
	// EnvPGConnString is the environment variable examined for a DSN for a
	// pre-existing database engine. If unset, an appropriate database will
	// attempt to be downloaded and run.
	EnvPGConnString = "POSTGRES_CONNECTION_STRING"

	// EnvPGVersion is the environment variable examined for the version of
	// PostgreSQL used if an embedded binary would be used.
	EnvPGVersion = `PGVERSION`

	loadUUID        = `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`
	createRole      = `CREATE ROLE %s LOGIN PASSWORD '%[1]s';`
	createDatabase  = `CREATE DATABASE %[2]s WITH OWNER %[1]s ENCODING 'UTF8';`
	killConnections = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`
	dropDatabase    = `DROP DATABASE %s;`
	dropRole        = `DROP ROLE %s;`
)

// NewDB generates a unique database for use in integration tests.
//
// The returned database has a random name and a dedicated owner role
// configured. The "uuid-ossp" extension is already loaded.
//
// DBSetup and NeedDB are expected to have been called correctly.
func NewDB(ctx context.Context, t testing.TB) (*DB, error) {
	cfg := pkgConfig.Copy()
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	cfg.MaxConns = 10
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

	cfg = cfg.Copy()
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

	cfg = cfg.Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = role
	t.Logf("config: %+v", struct {
		Host     string
		Database string
		User     string
		Password string
		Port     uint16
	}{
		Host:     cfg.ConnConfig.Host,
		Port:     cfg.ConnConfig.Port,
		Database: cfg.ConnConfig.Database,
		User:     cfg.ConnConfig.User,
		Password: cfg.ConnConfig.Password,
	})
	cfg.ConnConfig.Logger = nil

	return &DB{
		cfg: cfg,
	}, nil
}

// DB is a handle for connecting to and cleaning up a test database.
type DB struct {
	cfg *pgxpool.Config
}

// Config returns a pgxpool.Config for the test database.
func (db *DB) Config() *pgxpool.Config {
	return db.cfg.Copy()
}

// Close tears down the created database.
func (db *DB) Close(ctx context.Context, t testing.TB) {
	cfg := pkgConfig.Copy()
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
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

// NeedDB is like Skip, except that the test will run if the needed binaries
// have been fetched.
//
// See the example for usage.
func NeedDB(t testing.TB) {
	t.Helper()
	if skip && binUncached(t) {
		t.Skip("skipping integration test: would need to fetch binaries")
	}
	up.Do(startEmbedded(t))
}

// DBSetup queues setup and teardown for a postgres engine instance. If the
// "integration" build tag is not provided, then nothing is done. If the
// environment variable at EnvPGConnString is populated and the "integration"
// build tag is provided, then the value of that environment variable is used
// instead of an embedded postgres binary.
//
// See the example for usage.
func DBSetup() func() {
	dsn := os.Getenv(EnvPGConnString)
	if dsn != "" {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			panic(err)
		}
		pkgConfig = cfg
		up.Do(func() {}) // Trip the sync.Once
		// Database was started externally, we don't have to arrange to have it
		// torn down.
		return func() {}
	}

	return func() {
		if pkgDB != nil {
			pkgDB.Stop()
		}
	}
}

func startEmbedded(t testing.TB) func() {
	return func() {
		pkgDB = &Engine{}
		if err := pkgDB.Start(t); err != nil {
			t.Error(err)
			return
		}
		cfg, err := pgxpool.ParseConfig(pkgDB.DSN)
		if err != nil {
			t.Error(err)
			return
		}
		pkgConfig = cfg
	}
}
