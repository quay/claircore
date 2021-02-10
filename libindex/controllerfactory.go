package libindex

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/controller"
	"github.com/quay/claircore/internal/indexer/fetcher"
	"github.com/quay/claircore/internal/indexer/layerscanner"
	"github.com/quay/claircore/pkg/distlock/postgres"
)

// ControllerFactory is a factory method to return a Controller during libindex runtime.
type ControllerFactory func(_ context.Context, lib *Libindex, opts *Opts) (*controller.Controller, error)

// controllerFactory is the default ControllerFactory
func controllerFactory(ctx context.Context, lib *Libindex, opts *Opts) (*controller.Controller, error) {
	ft := fetcher.New(lib.client, opts.LayerFetchOpt)
	cfg, err := pgxpool.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = 1
	cfg.MaxConnIdleTime = time.Minute * 5
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	// BUG(hank) The pool is never explicitly closed.

	// convert libindex.Opts to indexer.Opts
	sOpts := &indexer.Opts{
		Store:         lib.store,
		ScanLock:      postgres.NewPool(pool, opts.ScanLockRetry),
		Fetcher:       ft,
		Ecosystems:    opts.Ecosystems,
		Vscnrs:        lib.vscnrs,
		Client:        lib.client,
		ScannerConfig: opts.ScannerConfig,
	}
	sOpts.LayerScanner, err = layerscanner.New(ctx, opts.LayerScanConcurrency, sOpts)
	if err != nil {
		return nil, err
	}

	s := controller.New(sOpts)
	return s, nil
}
