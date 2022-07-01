package libvuln

import (
	"net/http"
	"time"

	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	DefaultUpdateInterval  = 30 * time.Minute
	DefaultUpdateWorkers   = 10
	DefaultMaxConnPool     = 50
	DefaultUpdateRetention = 2
)

type Options struct {
	// Store is the interface used to persist and retrieve vulnerabilites
	// for of matching.
	Store datastore.MatcherStore
	// Locker provides system-wide locks for the updater subsystem. If the
	// matching work is distributed the lock should be backed by a distributed
	// store.
	Locker LockSource
	// An interval on which Libvuln will check for new security database
	// updates.
	//
	// This duration will have jitter added to it, to help with smearing load on
	// installations.
	UpdateInterval time.Duration
	// A slice of strings representing which updaters libvuln will create.
	//
	// If nil all default UpdaterSets will be used.
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string
	// A list of out-of-tree updaters to run.
	//
	// This list will be merged with any defined UpdaterSets.
	//
	// If you desire no updaters to run do not add an updater
	// into this slice.
	Updaters []driver.Updater
	// A slice of strings representing which
	// matchers will be used.
	//
	// If nil all default Matchers will be used
	//
	// The following names are supported by default:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "python"
	// "rhel"
	// "suse"
	// "ubuntu"
	// "crda" - remotematcher calls hosted api via RPC.
	MatcherNames []string

	// Config holds configuration blocks for MatcherFactories and Matchers,
	// keyed by name.
	MatcherConfigs map[string]driver.MatcherConfigUnmarshaler

	// A list of out-of-tree matchers you'd like libvuln to
	// use.
	//
	// This list will me merged with the default matchers.
	Matchers []driver.Matcher

	// Enrichers is a slice of enrichers to use with all VulnerabilityReport
	// requests.
	Enrichers []driver.Enricher

	// UpdateWorkers controls the number of update workers running concurrently.
	// If less than or equal to zero, a sensible default will be used.
	UpdateWorkers int

	// UpdateRetention controls the number of updates to retain between
	// garbage collection periods.
	//
	// The lowest possible value is 2 in order to compare updates for notification
	// purposes.
	UpdateRetention int

	// If set to true, there will not be a goroutine launched to periodically
	// run updaters.
	DisableBackgroundUpdates bool

	// UpdaterConfigs is a map of functions for configuration of Updaters.
	UpdaterConfigs map[string]driver.ConfigUnmarshaler

	// Client is an http.Client for use by all updaters. If unset,
	// http.DefaultClient will be used.
	Client *http.Client
}
