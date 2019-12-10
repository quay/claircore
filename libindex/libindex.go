package libindex

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/controller"
)

// Libindex implements the method set for scanning and indexing a Manifest.
type Libindex struct {
	// holds dependencies for creating a libindex instance
	*Opts
	// convenience field for creating scan-time resources that require a database
	db *sqlx.DB
	// a Store which will be shared between scanner instances
	store indexer.Store
	// a sharable http client
	client *http.Client
	logger zerolog.Logger
}

// New creates a new instance of libindex
func New(ctx context.Context, opts *Opts) (*Libindex, error) {
	logger := zerolog.Ctx(ctx).With().Str("component", "libindex").Logger()
	err := opts.Parse()
	if err != nil {
		logger.Error().Msgf("failed to parse opts: %v", err)
		return nil, fmt.Errorf("failed to parse opts: %v", err)
	}

	db, store, err := initStore(ctx, opts)
	if err != nil {
		return nil, err
	}
	logger.Info().Msg("created database connection")

	l := &Libindex{
		Opts:   opts,
		db:     db,
		store:  store,
		client: &http.Client{},
		logger: logger,
	}

	// register any new scanners.
	pscnrs, dscnrs, rscnrs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems)
	vscnrs := indexer.MergeVS(pscnrs, dscnrs, rscnrs)
	err = l.store.RegisterScanners(ctx, vscnrs)
	if err != nil {
		l.logger.Error().Msgf("failed to register configured scanners: %v", err)
		return nil, fmt.Errorf("failed to register configured scanners: %v", err)
	}
	l.logger.Info().Msg("registered configured scanners")
	l.Opts.vscnrs = vscnrs
	return l, nil
}

// Index performs a scan and index of each layer within the provided Manifest.
//
// If the index operation cannot start an error will be returned.
// If an error occurs during scan the error will be propagated inside the IndexReport.
func (l *Libindex) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	l.logger.Info().Msgf("received scan request for manifest hash: %v", manifest.Hash)
	c, err := l.ControllerFactory(l, l.Opts)
	if err != nil {
		l.logger.Error().Msgf("scanner factory failed to construct a scanner: %v", err)
		return nil, fmt.Errorf("scanner factory failed to construct a scanner: %v", err)
	}
	rc := l.index(ctx, c, manifest)
	return rc, nil
}

func (l *Libindex) index(ctx context.Context, s *controller.Controller, m *claircore.Manifest) *claircore.IndexReport {
	// attempt to get lock
	l.logger.Debug().Msgf("obtaining lock to scan manifest: %v", m.Hash)
	// will block until available or ctx times out
	err := s.Lock(ctx, m.Hash)
	if err != nil {
		// something went wrong with getting a lock
		// this is not an error saying another process has the lock
		l.logger.Error().Msgf("unexpected error acquiring lock: %v", err)
		ir := &claircore.IndexReport{
			Success: false,
			Err:     fmt.Sprintf("unexpected error acquiring lock: %v", err),
		}
		// best effort to push to persistence since we are about to bail anyway
		_ = l.store.SetIndexReport(ctx, ir)
		return ir
	}
	defer s.Unlock()
	l.logger.Info().Msgf("passing control of manifest %v scan to implemented scanner", m.Hash)
	ir := s.Index(ctx, m)
	return ir
}

// IndexReport retrieves an IndexReport for a particular manifest hash, if it exists.
func (l *Libindex) IndexReport(ctx context.Context, hash string) (*claircore.IndexReport, bool, error) {
	res, ok, err := l.store.IndexReport(ctx, hash)
	return res, ok, err
}
