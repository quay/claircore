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

// UpdateOperations returns UpdateOperations in date descending order keyed by the
// Updater name
func (l *Libvuln) UpdateOperations(ctx context.Context, updaters []string) (map[string][]*driver.UpdateOperation, error) {
	UOs, err := l.store.GetUpdateOperations(ctx, updaters)
	if err != nil {
		return nil, err
	}
	return UOs, nil
}

// DeleteUpdateOperations removes one or more update operations and their
// associated vulnerabilities from the vulnerability database.
func (l *Libvuln) DeleteUpdateOperations(ctx context.Context, UOIDs []string) error {
	err := l.store.DeleteUpdateOperations(ctx, UOIDs)
	return err
}

// UpdateOperationDiff returns an UpdateDiff resulting from UO_B being applied to
// UO_A
func (l *Libvuln) UpdateOperationDiff(ctx context.Context, UOID_A, UOID_B string) (*driver.UpdateDiff, error) {
	diff, err := l.store.GetUpdateOperationDiff(ctx, UOID_A, UOID_B)
	if err != nil {
		return nil, err
	}
	return diff, nil
}
