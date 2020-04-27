package libvuln

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/ubuntu"
)

const (
	DefaultUpdateInterval         = 30 * time.Minute
	DefaultUpdaterInitConcurrency = 10
	DefaultMaxConnPool            = 50
)

type Opts struct {
	// The maximum number of database connections in the
	// connection pool.
	MaxConnPool int32
	// A connection string to the database Lbvuln will use.
	ConnString string
	// An interval on which Libvuln will check for new security
	// database updates.
	UpdateInterval time.Duration
	// Determines if Livuln will manage database migrations
	Migrations bool
	// A pointer to a slice of strings representing which
	// updaters libvuln will create.
	//
	// If nil all default UpdaterSets will be used
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
	// A list of out-of-tree matchers you'd like libvuln to
	// use.
	//
	// This list will me merged with the default matchers.
	Matchers []driver.Matcher
}

// defaultMacheter is a variable containing
// all the matchers libvuln will use to match
// index records to vulnerabilities.
var defaultMatchers = []driver.Matcher{
	&alpine.Matcher{},
	&aws.Matcher{},
	&debian.Matcher{},
	&python.Matcher{},
	&ubuntu.Matcher{},
	&rhel.Matcher{},
}

// parse is an internal method for constructing
// the necessary Updaters and Matchers for Libvuln
// usage
func (o *Opts) parse(ctx context.Context) error {
	// required
	if o.ConnString == "" {
		return fmt.Errorf("no connection string provided")
	}

	// optional
	if o.UpdateInterval == 0 || o.UpdateInterval < time.Minute {
		o.UpdateInterval = DefaultUpdateInterval
	}
	if o.MaxConnPool == 0 {
		o.MaxConnPool = DefaultMaxConnPool
	}

	// merge default matchers with any out-of-tree specified
	o.Matchers = append(o.Matchers, defaultMatchers...)

	// determine which updaters should be populated
	set, err := updaterSets(ctx, o.UpdaterSets)
	if err != nil {
		return fmt.Errorf("failed to create updater sets: %v", err)
	}
	// merge determined updaters with any out-of-tree updaters
	o.Updaters = append(o.Updaters, set.Updaters()...)

	return nil
}
