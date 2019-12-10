package libvuln

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnscanner"
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
	logger       zerolog.Logger
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Opts) (*Libvuln, error) {
	logger := log.With().Str("component", "libvuln").Logger()
	err := opts.Parse()
	if err != nil {
		return nil, err
	}
	logger.Info().Msgf("initializing store with pool size: %v ", opts.MaxConnPool)
	db, vulnstore, err := initStore(ctx, opts)
	if err != nil {
		return nil, err
	}
	eC := make(chan error, 1024)
	dC := make(chan context.CancelFunc, 1)
	// block on updater initialization.
	logger.Info().Msg("beginning updater initialization")
	go initUpdaters(opts, db, vulnstore, dC, eC)
	killUpdaters := <-dC
	logger.Info().Msg("updaters initialized")
	for err := range eC {
		logger.Error().Msgf("error from updater: %v", err)
	}
	l := &Libvuln{
		store:        vulnstore,
		db:           db,
		matchers:     opts.Matchers,
		killUpdaters: killUpdaters,
		logger:       logger,
	}
	logger.Info().Msg("libvuln initialized")
	return l, nil
}

// Scan creates a VulnerabilityReport given a manifest's IndexReport.
func (l *Libvuln) Scan(ctx context.Context, sr *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	vs := vulnscanner.New(l.store, l.matchers)
	return vs.Scan(ctx, sr)
}
