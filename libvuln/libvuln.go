package libvuln

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// Libvuln exports methods for scanning an IndexReport and created
// a VulnerabilityReport.
//
// Libvuln also runs background updaters which keep the vulnerability
// database consistent.
type Libvuln struct {
	store        vulnstore.Store
	db           *sqlx.DB
	matchers     []driver.Matcher
	killUpdaters context.CancelFunc
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Opts) (*Libvuln, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/New").
		Logger()
	ctx = log.WithContext(ctx)
	err := opts.Parse()
	if err != nil {
		return nil, err
	}
	log.Info().
		Int32("count", opts.MaxConnPool).
		Msg("initializing store")
	db, vulnstore, err := initStore(ctx, opts)
	if err != nil {
		return nil, err
	}
	eC := make(chan error, 1024)
	dC := make(chan context.CancelFunc, 1)
	// block on updater initialization.
	log.Info().Msg("updater initialization start")
	go initUpdaters(ctx, opts, db, vulnstore, dC, eC)
	killUpdaters := <-dC
	log.Info().Msg("updater initialization done")
	for err := range eC {
		log.Warn().
			Err(err).
			Msg("updater error")
	}
	l := &Libvuln{
		store:        vulnstore,
		db:           db,
		matchers:     opts.Matchers,
		killUpdaters: killUpdaters,
	}
	log.Info().Msg("libvuln initialized")
	return l, nil
}

// Scan creates a VulnerabilityReport given a manifest's IndexReport.
func (l *Libvuln) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	return matcher.Match(ctx, ir, l.matchers, l.store)
}
