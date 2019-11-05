package libscan

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/controller"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
)

// Libscan is an interface exporting the public methods of our library.
type Libscan interface {
	// Scan performs an async scan of a manifest and produces a claircore.ScanReport.
	// Errors encountered before scan begins are returned in the error variable.
	// Errors encountered during scan are populated in the Err field of the claircore.ScanReport
	Scan(ctx context.Context, manifest *claircore.Manifest) (ResultChannel <-chan *claircore.ScanReport, err error)
	// ScanReport tries to retrieve a claircore.ScanReport given the image hash.
	// bool informs caller if found.
	ScanReport(ctx context.Context, hash string) (*claircore.ScanReport, bool, error)
}

// libscan implements libscan.Libscan interface
type libscan struct {
	// holds dependencies for creating a libscan instance
	*Opts
	// convenience field for creating scan-time resources that require a database
	db *sqlx.DB
	// a Store which will be shared between scanner instances
	store scanner.Store
	// a sharable http client
	client *http.Client
	logger zerolog.Logger
}

// New creates a new instance of Libscan
func New(ctx context.Context, opts *Opts) (Libscan, error) {
	logger := zerolog.Ctx(ctx).With().Str("component", "libscan").Logger()
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

	l := &libscan{
		Opts:   opts,
		db:     db,
		store:  store,
		client: &http.Client{},
		logger: logger,
	}

	// register any new scanners.
	pscnrs, dscnrs, rscnrs, err := scanner.EcosystemsToScanners(ctx, opts.Ecosystems)
	vscnrs := scanner.MergeVS(pscnrs, dscnrs, rscnrs)

	err = l.store.RegisterScanners(ctx, vscnrs)
	if err != nil {
		l.logger.Error().Msgf("failed to register configured scanners: %v", err)
		return nil, fmt.Errorf("failed to register configured scanners: %v", err)
	}
	l.logger.Info().Msg("registered configured scanners")

	l.Opts.vscnrs = vscnrs
	return l, nil
}

// Scan performs an ansyc scan of the manifest and produces a ScanReport. a channel is returned a caller may block on
func (l *libscan) Scan(ctx context.Context, manifest *claircore.Manifest) (<-chan *claircore.ScanReport, error) {
	l.logger.Info().Msgf("received scan request for manifest hash: %v", manifest.Hash)

	rc := make(chan *claircore.ScanReport, 1)

	s, err := l.ControllerFactory(l, l.Opts)
	if err != nil {
		l.logger.Error().Msgf("scanner factory failed to construct a scanner: %v", err)
		return nil, fmt.Errorf("scanner factory failed to construct a scanner: %v", err)
	}

	go l.scan(ctx, s, rc, manifest)

	return rc, nil
}

// scan performs the business logic of starting a scan.
func (l *libscan) scan(ctx context.Context, s *controller.Controller, rc chan *claircore.ScanReport, m *claircore.Manifest) {
	// once scan is finished close the rc channel incase callers are ranging
	defer close(rc)

	// attempt to get lock
	l.logger.Debug().Msgf("obtaining lock to scan manifest: %v", m.Hash)
	// will block until available or ctx times out
	err := s.Lock(ctx, m.Hash)
	if err != nil {
		// something went wrong with getting a lock
		// this is not an error saying another process has the lock
		l.logger.Error().Msgf("unexpected error acquiring lock: %v", err)
		sr := &claircore.ScanReport{
			Success: false,
			Err:     fmt.Sprintf("unexpected error acquiring lock: %v", err),
		}
		// best effort to push to persistence since we are about to bail anyway
		_ = l.store.SetScanReport(ctx, sr)

		select {
		case rc <- sr:
			return
		default:
			return
		}
	}
	defer s.Unlock()

	l.logger.Info().Msgf("passing control of manifest %v scan to implemented scanner", m.Hash)
	sr := s.Scan(ctx, m)

	select {
	case rc <- sr:
	default:
	}
}

// ScanReport retrieves a ScanReport struct from persistence if it exists. if the ScanReport does not exist
// the bool value will be false.
func (l *libscan) ScanReport(ctx context.Context, hash string) (*claircore.ScanReport, bool, error) {
	res, ok, err := l.store.ScanReport(ctx, hash)
	return res, ok, err
}
