package libindex

import (
	"time"

	"github.com/quay/claircore/indexer"
)

const (
	DefaultScanLockRetry        = 5 * time.Second
	DefaultLayerScanConcurrency = 10
)

// Options are dependencies and options for constructing an instance of libindex
type Options struct {
	// Store is the interface used to persist and retrieve results of indexing.
	Store indexer.Store
	// Locker provides system-wide locks. If the indexing work is distributed the
	// lock should be backed by a distributed store.
	Locker LockSource
	// FetchArena is an interface tied to the lifecycle of LibIndex to enable management
	// of the filesystem while separate processes are dealing with layers, for example:
	// you can reference count downloaded layer files to avoid racing.
	FetchArena Arena
	// ScanLockRetry specifies how often we should try to acquire a lock for scanning a
	// given manifest if lock is taken.
	ScanLockRetry time.Duration
	// LayerScanConcurrency specifies the number of layers to be scanned in parallel.
	LayerScanConcurrency int
	// LayerFetchOpt is unused and kept here for backwards compatibility.
	LayerFetchOpt interface{}
	// NoLayerValidation controls whether layers are checked to actually be
	// content-addressed. With this option toggled off, callers can trigger
	// layers to be indexed repeatedly by changing the identifier in the
	// manifest.
	NoLayerValidation bool
	// ControllerFactory provides an alternative method for creating a scanner during libindex runtime
	// if nil the default factory will be used. useful for testing purposes
	ControllerFactory ControllerFactory
	// Ecosystems a list of ecosystems to use which define which package databases and coalescing methods we use
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
}
