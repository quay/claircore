package integration

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgconn"
	pgxpoolv4 "github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"
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
// TODO(crozzy): Remove pgx v4 code after ctxlock stops supporting v4.
func NewDB(ctx context.Context, t testing.TB) (*DB, error) {
	dbid, roleid := mkIDs()
	database := fmt.Sprintf("db%x", dbid)
	role := fmt.Sprintf("role%x", roleid)
	cfg := configureDatabase(ctx, t, pkgConfig, database, role)
	if t.Failed() {
		return nil, fmt.Errorf("failed to create database")
	}
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

	cfg4, err := pgxpoolv4.ParseConfig(pkgConfig.ConnString())
	if err != nil {
		t.Error(err)
	}
	cfg4.ConnConfig.User = role
	cfg4.ConnConfig.Password = role
	cfg4.ConnConfig.Database = database

	return &DB{
		cfg:  cfg,
		cfg4: cfg4,
	}, nil
}

func configureDatabase(ctx context.Context, t testing.TB, root *pgxpool.Config, database, role string) *pgxpool.Config {
	var cfg *pgxpool.Config
	// First, connect as the superuser to create the new database and role.
	cfg = root.Copy()
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger: testingadapter.NewLogger(t),
	}
	cfg.MaxConns = 10
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Error(err)
		return nil
	}
	// The creation commands don't have "IF NOT EXISTS" forms, so check for the
	// specific error codes that mean they already exist.
	var pgErr *pgconn.PgError
	_, err = conn.Exec(ctx, fmt.Sprintf(createRole, role))
	switch {
	case errors.Is(err, nil):
	case errors.As(err, &pgErr):
		if pgErr.Code == "42710" {
			t.Log("expected error:", pgErr.Message)
			break
		}
		fallthrough
	default:
		t.Error(err)
	}
	_, err = conn.Exec(ctx, fmt.Sprintf(createDatabase, role, database))
	switch {
	case errors.Is(err, nil):
	case errors.As(err, &pgErr):
		if pgErr.Code == "42P04" {
			t.Log("expected error:", pgErr.Message)
			break
		}
		fallthrough
	default:
		t.Error(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Error(err)
	}
	if t.Failed() {
		return nil
	}

	// Next, connect to the newly created database as the superuser to load the
	// uuid extension
	cfg = cfg.Copy()
	cfg.ConnConfig.Database = database
	conn, err = pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Error(err)
		return nil
	}
	if _, err := conn.Exec(ctx, loadUUID); err != nil {
		t.Error(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Error(err)
	}
	if t.Failed() {
		return nil
	}

	// Finally, return a config setup to connect as the new role to the new
	// database.
	cfg = root.Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = role
	cfg.ConnConfig.Database = database

	return cfg
}

// DB is a handle for connecting to and cleaning up a test database.
//
// If [testing.Verbose] reports true, the database engine will be run with the
// "auto_explain" module enabled. See the [auto_explain documentation] for more
// information. Setting the environment variable "PGEXPLAIN_FORMAT" will control
// the output format. This does not apply when the test harness is not
// controlling the database.
//
// [auto_explain documentation]: https://www.postgresql.org/docs/current/auto-explain.html
type DB struct {
	cfg    *pgxpool.Config
	cfg4   *pgxpoolv4.Config
	noDrop bool
}

func (db *DB) String() string {
	const dsnFmt = `host=%s port=%d database=%s user=%s password=%s sslmode=disable`
	return fmt.Sprintf(dsnFmt,
		db.cfg.ConnConfig.Host,
		db.cfg.ConnConfig.Port,
		db.cfg.ConnConfig.Database,
		db.cfg.ConnConfig.User,
		db.cfg.ConnConfig.Password)
}

// Config returns a pgxpool.Config for the test database.
func (db *DB) Config() *pgxpool.Config {
	return db.cfg.Copy()
}

func (db *DB) Configv4() *pgxpoolv4.Config {
	return db.cfg4.Copy()
}

// Close tears down the created database.
func (db *DB) Close(ctx context.Context, t testing.TB) {
	cfg := pkgConfig.Copy()
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger: testingadapter.NewLogger(t),
	}
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, killConnections, db.cfg.ConnConfig.Database); err != nil {
		t.Error(err)
	}

	if !db.noDrop {
		if _, err := conn.Exec(ctx, fmt.Sprintf(dropDatabase, db.cfg.ConnConfig.Database)); err != nil {
			t.Error(err)
		}
		if _, err := conn.Exec(ctx, fmt.Sprintf(dropRole, db.cfg.ConnConfig.User)); err != nil {
			t.Error(err)
		}
	}
	db.cfg = nil
}

// NeedDB is like Skip, except that the test will run if the needed binaries
// have been fetched.
//
// See the example for usage.
func NeedDB(t testing.TB) {
	t.Helper()
	if testing.Short() {
		t.Skip(`skipping integration test: short tests`)
	}
	if inGHA {
		up.Do(startGithubActions(t))
		return
	}
	if externalDB {
		t.Log("using preconfigured external database")
		up.Do(func() {
			cfg, err := pgxpool.ParseConfig(os.Getenv(EnvPGConnString))
			if err != nil {
				t.Fatal(err)
			}
			pkgConfig = cfg
			// Database was started externally, we don't have to arrange to have it
			// torn down.
		})
		return
	}

	t.Log("using embedded database")
	embedDB.DiscoverVersion(t)
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
	// This used to do a bunch of setup, but that got pretty gnarly.
	//
	// Most of the complexity was moved into [NeedDB] and helper functions run
	// under the [up] sync.Once, because there's a [testing.T] that can actually
	// log things.
	return func() {
		if pkgDB != nil {
			pkgDB.Stop()
		}
	}
}
