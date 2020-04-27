package libvuln

import (
	"context"

	"github.com/google/uuid"
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

	err := opts.parse(ctx)
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

	// block on updater initialization.
	eC := make(chan error, 1024)
	dC := make(chan context.CancelFunc, 1)
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
func (l *Libvuln) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	return l.store.GetUpdateOperations(ctx, updaters...)
}

// DeleteUpdateOperations removes one or more update operations and their
// associated vulnerabilities from the vulnerability database.
func (l *Libvuln) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) error {
	return l.store.DeleteUpdateOperations(ctx, ref...)
}

// UpdateDiff returns an UpdateDiff describing the changes between prev
// and cur.
func (l *Libvuln) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return l.store.GetUpdateDiff(ctx, prev, cur)
}

// LatestUpdateOperations returns references for the latest update for every
// known updater.
//
// These references are okay to expose externally.
func (l *Libvuln) LatestUpdateOperations(ctx context.Context) (map[string]uuid.UUID, error) {
	return l.store.GetLatestUpdateRefs(ctx)
}

// LatestUpdateOperation returns a reference to the latest known update.
//
// This can be used by clients to determine if a call to Scan is likely to
// return new results.
func (l *Libvuln) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	return l.store.GetLatestUpdateRef(ctx)
}
