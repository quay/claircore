package libvuln

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/migrations"
)

const (
	DefaultUpdateInterval  = 30 * time.Minute
	DefaultUpdateWorkers   = 10
	DefaultMaxConnPool     = 50
	DefaultUpdateRetention = 2
)

type Opts struct {
	// The maximum number of database connections in the
	// connection pool.
	MaxConnPool int32
	// A connection string to the database Libvuln will use.
	//
	// TODO(hank) This should be a factory function so the data store can be
	// a clean abstraction.
	ConnString string
	// An interval on which Libvuln will check for new security database
	// updates.
	//
	// This duration will have jitter added to it, to help with smearing load on
	// installations.
	UpdateInterval time.Duration
	// Determines if Libvuln will manage database migrations
	Migrations bool
	// A slice of strings representing which updaters libvuln will create.
	//
	// If nil all default UpdaterSets will be used.
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string
	// A list of out-of-tree updaters to run.
	//
	// This list will be merged with any defined UpdaterSets.
	//
	// If you desire no updaters to run do not add an updater
	// into this slice.
	Updaters []driver.Updater
	// A slice of strings representing which
	// matchers will be used.
	//
	// If nil all default Matchers will be used
	//
	// The following names are supported by default:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "python"
	// "rhel"
	// "suse"
	// "ubuntu"
	// "crda" - remotematcher calls hosted api via RPC.
	MatcherNames []string

	// Config holds configuration blocks for MatcherFactories and Matchers,
	// keyed by name.
	MatcherConfigs map[string]driver.MatcherConfigUnmarshaler

	// A list of out-of-tree matchers you'd like libvuln to
	// use.
	//
	// This list will me merged with the default matchers.
	Matchers []driver.Matcher

	// Enrichers is a slice of enrichers to use with all VulnerabilityReport
	// requests.
	Enrichers []driver.Enricher

	// UpdateWorkers controls the number of update workers running concurrently.
	// If less than or equal to zero, a sensible default will be used.
	UpdateWorkers int

	// UpdateRetention controls the number of updates to retain between
	// garbage collection periods.
	//
	// The lowest possible value is 2 in order to compare updates for notification
	// purposes.
	UpdateRetention int

	// If set to true, there will not be a goroutine launched to periodically
	// run updaters.
	DisableBackgroundUpdates bool

	// UpdaterConfigs is a map of functions for configuration of Updaters.
	UpdaterConfigs map[string]driver.ConfigUnmarshaler

	// Client is an http.Client for use by all updaters. If unset,
	// http.DefaultClient will be used.
	Client *http.Client
}

// parse is an internal method for constructing
// the necessary Updaters and Matchers for Libvuln
// usage
func (o *Opts) parse(ctx context.Context) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libvuln/Opts.parse"))
	// required
	if o.UpdateRetention == 1 || o.UpdateRetention < 0 {
		return fmt.Errorf("update retention must be 0 or greater then 1")
	}

	if o.UpdateInterval == 0 || o.UpdateInterval < time.Minute {
		o.UpdateInterval = DefaultUpdateInterval
	}
	// This gives us a ±60 second range, rounded to the nearest tenth of a
	// second.
	const jitter = 120000
	ms := time.Duration(rand.Intn(jitter)-(jitter/2)) * time.Microsecond
	ms = ms.Round(100 * time.Millisecond)
	o.UpdateInterval += ms

	if o.MaxConnPool == 0 {
		o.MaxConnPool = DefaultMaxConnPool
	}
	if o.UpdateWorkers <= 0 {
		o.UpdateWorkers = DefaultUpdateWorkers
	}

	if o.Client == nil {
		zlog.Warn(ctx).
			Msg("using default HTTP client; this will become an error in the future")
		o.Client = http.DefaultClient // TODO(hank) Remove DefaultClient
	}
	if o.UpdaterConfigs == nil {
		o.UpdaterConfigs = make(map[string]driver.ConfigUnmarshaler)
	}

	return nil
}

// Pool creates and returns a configured pxgpool.Pool.
func (o *Opts) pool(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(o.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = o.MaxConnPool
	const appnameKey = `application_name`
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params[appnameKey]; !ok {
		params[appnameKey] = `libvuln`
	}

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Pool: %v", err)
	}
	return pool, nil
}

// Migrations performs migrations if the configuration asks for it.
func (o *Opts) migrations(_ context.Context) error {
	// The migrate package doesn't use the context, which is... disconcerting.
	if !o.Migrations {
		return nil
	}
	cfg, err := pgx.ParseConfig(o.ConnString)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", stdlib.RegisterConnConfig(cfg))
	if err != nil {
		return err
	}
	defer db.Close()

	migrator := migrate.NewPostgresMigrator(db)
	migrator.Table = migrations.MigrationTable
	if err := migrator.Exec(migrate.Up, migrations.Migrations...); err != nil {
		return err
	}

	return nil
}
