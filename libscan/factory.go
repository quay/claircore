package libscan

import (
	"fmt"

	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/internal/scanner/controller"
	"github.com/quay/claircore/internal/scanner/fetcher"
	"github.com/quay/claircore/internal/scanner/layerscanner"
	"github.com/quay/claircore/pkg/distlock"
	dlpg "github.com/quay/claircore/pkg/distlock/postgres"
)

// ControllerFactory is a factory method to return a Controller during libscan runtime.
type ControllerFactory func(lib *libscan, opts *Opts) (*controller.Controller, error)

// controllerFactory is the default ControllerFactory
func controllerFactory(lib *libscan, opts *Opts) (*controller.Controller, error) {
	// add other distributed locking implementations here as they grow
	var sc distlock.Locker
	switch opts.ScanLock {
	case PostgresSL:
		sc = dlpg.NewLock(lib.db, opts.ScanLockRetry)
	default:
		return nil, fmt.Errorf("provided ScanLock opt is unsupported")
	}

	// add other fetcher implementations here as they grow
	var ft scanner.Fetcher
	ft = fetcher.New(lib.client, nil, opts.LayerFetchOpt)

	// convert libscan.Opts to scanner.Opts
	sOpts := &scanner.Opts{
		Store:      lib.store,
		ScanLock:   sc,
		Fetcher:    ft,
		Ecosystems: opts.Ecosystems,
		Vscnrs:     lib.vscnrs,
	}

	// add other layer scanner implementations as they grow
	sOpts.LayerScanner = layerscanner.New(opts.LayerScanConcurrency, sOpts)
	s := controller.New(sOpts)
	return s, nil
}
