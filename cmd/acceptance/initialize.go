package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/migrations"
	"github.com/remind101/migrate"
)

// deps is a container for all dependencies required to make
// fixtures
type deps struct {
	libI      *libindex.Libindex
	libV      *libvuln.Libvuln
	vulnStore vulnstore.Store
}

// initilize creates all the depedencies for creating fixtures
func initialize(ctx context.Context) (deps, error) {
	// TODO: it would be nicer to use the test database harnesses but
	// 1) they don't return a DSN
	// 2) they expect a *testing.T
	log.Print("creating libindex instance")
	iOpt := &libindex.Opts{
		ConnString: "host=localhost port=5434 user=claircore dbname=claircore sslmode=disable",
		Migrations: true,
	}
	libI, err := libindex.New(ctx, iOpt)
	if err != nil {
		return deps{}, fmt.Errorf("failed to create libindex instance: %v", err)
	}

	log.Print("creating libvuln instance")
	vOpt := &libvuln.Opts{
		ConnString: "host=localhost port=5434 user=claircore dbname=claircore sslmode=disable",
		Migrations: true,
		Updaters:   []driver.Updater{},
	}
	libV, err := libvuln.New(ctx, vOpt)
	if err != nil {
		return deps{}, fmt.Errorf("failed to create libvuln instance: %v", err)
	}

	log.Print("creating vulnstore instance")
	_, vulnStore, err := initStore(ctx, vOpt)
	if err != nil {
		return deps{}, fmt.Errorf("failed to create vulnstore instance: %v", err)
	}

	return deps{libI, libV, vulnStore}, nil
}

// initStore initializes a vulsntore and returns the underlying db object also
func initStore(ctx context.Context, opts *libvuln.Opts) (*sqlx.DB, vulnstore.Store, error) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	// set conn pool size via libvuln.Opts
	cfg.MaxConns = opts.MaxConnPool
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	db, err := sqlx.Open("pgx", opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Open db: %v", err)
	}

	// do migrations if requested
	if opts.Migrations {
		migrator := migrate.NewPostgresMigrator(db.DB)
		migrator.Table = migrations.MigrationTable
		err := migrator.Exec(migrate.Up, migrations.Migrations...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := postgres.NewVulnStore(db, pool)
	return db, store, nil
}
