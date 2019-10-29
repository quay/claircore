package libscan

import (
	"fmt"
	"time"

	"github.com/quay/claircore/internal/scanner"
)

// DataStore tells libscan which backing persistence store to instantiate
type DataStore string

const (
	Postgres DataStore = "postgres"
)

// ScanLock tells libscan which distributed locking implementation to use
type ScanLock string

const (
	PostgresSL ScanLock = "postgres"
)

const (
	DefaultScanLockRetry        = 5 * time.Second
	DefaultLayerScanConcurrency = 10
	DefaultLayerFetchOpt        = scanner.OnDisk
)

// Opts are depedencies and options for constructing an instance of libscan
type Opts struct {
	// the datastore this instance of libscan will use
	DataStore DataStore
	// the connection string for the datastore specified above
	ConnString string
	// the type of ScanLock implementation to use. currently postgres is supported
	ScanLock ScanLock
	// how often we should try to acquire a lock for scanning a given manifest if lock is taken
	ScanLockRetry time.Duration
	// the number of layers to be scanned in parellel.
	LayerScanConcurrency int
	// how we store layers we fetch remotely. see LayerFetchOpt type def above for more details
	LayerFetchOpt scanner.LayerFetchOpt
	// provides an alternative method for creating a scanner during libscan runtime
	// if nil the default factory will be used. useful for testing purposes
	ControllerFactory ControllerFactory
	// a list of ecosystems to use which define which package databases and coalescing methods we use
	Ecosystems []*scanner.Ecosystem
	// a convenience method for holding a list of versioned scanners
	vscnrs scanner.VersionedScanners
}

func (o *Opts) Parse() error {
	// required
	if o.DataStore == "" {
		return fmt.Errorf("DataSource not provided")
	}
	if o.ConnString == "" {
		return fmt.Errorf("ConnString not provided")
	}
	if o.ScanLock == "" {
		return fmt.Errorf("ScanLock not provided")
	}
	if len(o.Ecosystems) == 0 {
		return fmt.Errorf("No ecosystems provided. cannot scan manifests")
	}

	// optional
	if o.ScanLockRetry == 0 {
		o.ScanLockRetry = DefaultScanLockRetry
	}
	if o.LayerScanConcurrency == 0 {
		o.LayerScanConcurrency = DefaultLayerScanConcurrency
	}
	if o.ControllerFactory == nil {
		o.ControllerFactory = controllerFactory
	}
	// for now force this to Tee to support layer stacking
	o.LayerFetchOpt = DefaultLayerFetchOpt

	return nil
}
