package libindex

import (
	"context"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rpm"
)

const (
	DefaultScanLockRetry        = 5 * time.Second
	DefaultLayerScanConcurrency = 10
	DefaultLayerFetchOpt        = indexer.OnDisk
)

// Opts are dependencies and options for constructing an instance of libindex
type Opts struct {
	// The connection string for the data store.
	//
	// TODO(hank) This should be a factory function so the data store can be
	// a clean abstraction.
	ConnString string
	// how often we should try to acquire a lock for scanning a given manifest if lock is taken
	ScanLockRetry time.Duration
	// the number of layers to be scanned in parallel.
	LayerScanConcurrency int
	// how we store layers we fetch remotely. see LayerFetchOpt type def above for more details
	LayerFetchOpt indexer.LayerFetchOpt
	// NoLayerValidation controls whether layers are checked to actually be
	// content-addressed. With this option toggled off, callers can trigger
	// layers to be indexed repeatedly by changing the identifier in the
	// manifest.
	NoLayerValidation bool
	// set to true to have libindex check and potentially run migrations
	Migrations bool
	// provides an alternative method for creating a scanner during libindex runtime
	// if nil the default factory will be used. useful for testing purposes
	ControllerFactory ControllerFactory
	// a list of ecosystems to use which define which package databases and coalescing methods we use
	Ecosystems []*indexer.Ecosystem
	// Airgap should be set to disallow any scanners that mark themselves as
	// making network calls.
	Airgap bool
	// ScannerConfig holds functions that can be passed into configurable
	// scanners. They're broken out by kind, and only used if a scanner
	// implements the appropriate interface.
	//
	// Providing a function for a scanner that's not expecting it is not a fatal
	// error.
	ScannerConfig struct {
		Package, Dist, Repo map[string]func(interface{}) error
	}
	// a convenience method for holding a list of versioned scanners
	vscnrs indexer.VersionedScanners
}

func (o *Opts) Parse(ctx context.Context) error {
	// optional
	if (o.ScanLockRetry == 0) || (o.ScanLockRetry < time.Second) {
		o.ScanLockRetry = DefaultScanLockRetry
	}
	if o.LayerScanConcurrency == 0 {
		o.LayerScanConcurrency = DefaultLayerScanConcurrency
	}
	if o.ControllerFactory == nil {
		o.ControllerFactory = controllerFactory
	}
	if o.Ecosystems == nil {
		o.Ecosystems = []*indexer.Ecosystem{
			dpkg.NewEcosystem(ctx),
			alpine.NewEcosystem(ctx),
			rhel.NewEcosystem(ctx),
			rpm.NewEcosystem(ctx),
			python.NewEcosystem(ctx),
			java.NewEcosystem(ctx),
		}
	}
	o.LayerFetchOpt = DefaultLayerFetchOpt

	return nil
}
