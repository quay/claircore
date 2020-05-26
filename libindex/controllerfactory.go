package libindex

import (
	"context"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/controller"
	"github.com/quay/claircore/internal/indexer/fetcher"
	"github.com/quay/claircore/internal/indexer/layerscanner"
	dlpg "github.com/quay/claircore/pkg/distlock/postgres"
)

// ControllerFactory is a factory method to return a Controller during libindex runtime.
type ControllerFactory func(_ context.Context, lib *Libindex, opts *Opts) (*controller.Controller, error)

// controllerFactory is the default ControllerFactory
func controllerFactory(ctx context.Context, lib *Libindex, opts *Opts) (*controller.Controller, error) {
	sc := dlpg.NewLock(lib.db, opts.ScanLockRetry)
	ft := fetcher.New(lib.client, opts.LayerFetchOpt)

	// convert libindex.Opts to indexer.Opts
	sOpts := &indexer.Opts{
		Store:         lib.store,
		ScanLock:      sc,
		Fetcher:       ft,
		Ecosystems:    opts.Ecosystems,
		Vscnrs:        lib.vscnrs,
		Client:        lib.client,
		ScannerConfig: opts.ScannerConfig,
	}
	var err error
	sOpts.LayerScanner, err = layerscanner.New(ctx, opts.LayerScanConcurrency, sOpts)
	if err != nil {
		return nil, err
	}

	s := controller.New(sOpts)
	return s, nil
}
