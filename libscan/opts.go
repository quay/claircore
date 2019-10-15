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
	DefaultLayerFetchOpt        = scanner.Tee
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
	// if nil the default factory will be used
	ScannerFactory ScannerFactory
	// provides an alternative method for specifying the package scanners used during libscan runtime
	// if nil the default factory will be used
	PackageScannerFactory PackageScannerFactory
	// provides an alternative method for specifying the distribution scanners used during libscan runtime
	// if nil the default factory will be used
	DistributionScannerFactory DistributionScannerFactory
	// provides an alternative method for specifying the repository scanners used during libscan runtime
	// if nil the default factory will be used
	RepositoryScannerFactory RepositoryScannerFactory
	// Computed after libscan initialization
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

	// optional
	if o.ScanLockRetry == 0 {
		o.ScanLockRetry = DefaultScanLockRetry
	}
	if o.LayerScanConcurrency == 0 {
		o.LayerScanConcurrency = DefaultLayerScanConcurrency
	}
	if o.ScannerFactory == nil {
		o.ScannerFactory = scannerFactory
	}
	if o.PackageScannerFactory == nil {
		o.PackageScannerFactory = packageScannerFactory
	}
	if o.DistributionScannerFactory == nil {
		o.DistributionScannerFactory = distributionScannerFactory
	}
	if o.RepositoryScannerFactory == nil {
		o.RepositoryScannerFactory = repositoryScannerFactory
	}

	// for now force this to Tee to support layer stacking
	o.LayerFetchOpt = DefaultLayerFetchOpt

	return nil
}
