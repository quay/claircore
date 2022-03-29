package libindex

import "time"

const (
	DefaultScanLockRetry        = 5 * time.Second
	DefaultLayerScanConcurrency = 10
	DefaultLayerFetchOpt        = indexer.OnDisk
)

// Options are dependencies and options for constructing an instance of libindex
type Options struct {
	// TODO(crozzy): docs
	Store      indexer.Store
	Locker     LockSource
	FetchArena FetchArena
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
