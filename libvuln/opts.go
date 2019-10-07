package libvuln

import (
	"fmt"
	"time"

	"github.com/quay/claircore/libvuln/driver"
)

// DataStore tells libvuln which backing persistence store to instantiate
type DataStore string

const (
	Postgres DataStore = "postgres"
)

// ScanLock tells libscan which distributed locking implementation to use
type UpdateLock string

const (
	PostgresSL UpdateLock = "postgres"
)

const (
	DefaultUpdateInterval         = 30 * time.Minute
	DefaultUpdaterInitConcurrency = 10
)

type Opts struct {
	// the datastore implementation libvuln should instantiate
	DataStore DataStore
	// the maximum size of the connection pool used by the database
	MaxConnPool int32
	// the connectiong string to the above data store implementation
	ConnString string
	// the update lock (distlock) implementation libvuln should instantiate
	UpdateLock UpdateLock
	// returns the matchers to be used during libvuln runtime
	Matchers []driver.Matcher
	// returns the updaters to run on an interval
	Updaters []driver.Updater
	// the interval at which updaters will update the vulnstore
	UpdateInterval time.Duration
	// number of updaters ran in parallel while libscan initializes. use this to tune io/cpu on library start when using many updaters
	UpdaterInitConcurrency int
}

func (o *Opts) Parse() error {
	// required
	if o.DataStore == "" {
		return fmt.Errorf("no store provided")
	}
	if o.ConnString == "" {
		return fmt.Errorf("no connection string provided")
	}
	if o.UpdateLock == "" {
		return fmt.Errorf("not distributed lock provided")
	}
	if o.UpdateInterval == 0 {
		o.UpdateInterval = DefaultUpdateInterval
	}
	if o.UpdaterInitConcurrency == 0 {
		o.UpdaterInitConcurrency = DefaultUpdaterInitConcurrency
	}
	return nil
}
