package libindex

import (
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/controller"
	"github.com/quay/claircore/internal/scanner/fetcher"
	"github.com/quay/claircore/internal/scanner/layerscanner"
	dlpg "github.com/quay/claircore/pkg/distlock/postgres"
)

// ControllerFactory is a factory method to return a Controller during libindex runtime.
type ControllerFactory func(lib *libindex, opts *Opts) (*controller.Controller, error)

// controllerFactory is the default ControllerFactory
func controllerFactory(lib *libindex, opts *Opts) (*controller.Controller, error) {
	sc := dlpg.NewLock(lib.db, opts.ScanLockRetry)
	ft := fetcher.New(lib.client, nil, opts.LayerFetchOpt)

	// convert libindex.Opts to scanner.Opts
	sOpts := &scanner.Opts{
		Store:      lib.store,
		ScanLock:   sc,
		Fetcher:    ft,
		Ecosystems: opts.Ecosystems,
		Vscnrs:     lib.vscnrs,
	}
	sOpts.LayerScanner = layerscanner.New(opts.LayerScanConcurrency, sOpts)

	s := controller.New(sOpts)
	return s, nil
}
