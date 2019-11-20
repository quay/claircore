package libindex

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/rpm"
)

const (
	DefaultScanLockRetry        = 5 * time.Second
	DefaultLayerScanConcurrency = 10
	DefaultLayerFetchOpt        = indexer.OnDisk
)

// Opts are depedencies and options for constructing an instance of libindex
type Opts struct {
	// the connection string for the datastore specified above
	ConnString string
	// how often we should try to acquire a lock for scanning a given manifest if lock is taken
	ScanLockRetry time.Duration
	// the number of layers to be scanned in parellel.
	LayerScanConcurrency int
	// how we store layers we fetch remotely. see LayerFetchOpt type def above for more details
	LayerFetchOpt indexer.LayerFetchOpt
	// provides an alternative method for creating a scanner during libindex runtime
	// if nil the default factory will be used. useful for testing purposes
	ControllerFactory ControllerFactory
	// a list of ecosystems to use which define which package databases and coalescing methods we use
	Ecosystems []*indexer.Ecosystem
	// a convenience method for holding a list of versioned scanners
	vscnrs indexer.VersionedScanners
}

func (o *Opts) Parse() error {
	// required
	if o.ConnString == "" {
		return fmt.Errorf("ConnString not provided")
	}

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
	if len(o.Ecosystems) == 0 {
		o.Ecosystems = []*indexer.Ecosystem{
			dpkg.NewEcosystem(context.Background()),
			alpine.NewEcosystem(context.Background()),
			rpm.NewEcosystem(context.Background()),
		}
	}
	o.LayerFetchOpt = DefaultLayerFetchOpt

	return nil
}
