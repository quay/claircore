package libvuln

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnscanner"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Libvuln is an interface exporting the public methods of our library.
type Libvuln interface {
	Scan(ctx context.Context, sr *claircore.ScanReport) (*claircore.VulnerabilityReport, error)
}

// libvuln implements the libvuln.Lubvuln interface
type libvuln struct {
	store        vulnstore.Store
	db           *sqlx.DB
	matchers     []driver.Matcher
	killUpdaters context.CancelFunc
	logger       zerolog.Logger
}

// New creates a new instance of the Libvuln library
func New(ctx context.Context, opts *Opts) (Libvuln, error) {
	logger := log.With().Str("component", "libvuln").Logger()

	err := opts.Parse()
	if err != nil {
		return nil, err
	}

	logger.Info().Msgf("initializing store %v and pool size: %v ", opts.DataStore, opts.MaxConnPool)
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

	l := &libvuln{
		store:        vulnstore,
		db:           db,
		matchers:     opts.Matchers,
		killUpdaters: killUpdaters,
		logger:       logger,
	}

	logger.Info().Msg("libvuln initialized")
	return l, nil
}

func (l *libvuln) Scan(ctx context.Context, sr *claircore.ScanReport) (*claircore.VulnerabilityReport, error) {
	vs := vulnscanner.New(l.store, l.matchers)
	return vs.Scan(ctx, sr)
}
