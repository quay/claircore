package libindex

import (
	"context"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/indexer/controller"
	"github.com/quay/claircore/indexer/layerscanner"
)

// ControllerFactory is a factory method to return a Controller during libindex runtime.
type ControllerFactory func(_ context.Context, lib *Libindex, opts *Options) (*controller.Controller, error)

// controllerFactory is the default ControllerFactory
func controllerFactory(ctx context.Context, lib *Libindex, opts *Options) (*controller.Controller, error) {
	// convert libindex.Opts to indexer.Opts
	sOpts := &indexer.Opts{
		Store:         lib.store,
		Realizer:      lib.fa.Realizer(ctx),
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
