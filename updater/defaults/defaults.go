// Package defaults sets updater defaults.
//
// Importing this package registers default updaters via its init function.
package defaults

import (
	"context"
	"sync"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/pyupio"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
	"github.com/quay/claircore/updater"
)

var (
	once   sync.Once
	regerr error
)

func init() {
	ctx, done := context.WithTimeout(context.Background(), 1*time.Minute)
	defer done()
	once.Do(func() { regerr = inner(ctx) })
}

// Error reports if an error was encountered when initializing the default
// updaters.
func Error() error {
	return regerr
}

func inner(ctx context.Context) error {
	rf, err := rhel.NewFactory(ctx, rhel.DefaultManifest)
	if err != nil {
		return err
	}
	updater.Register("rhel", rf)

	updater.Register("ubuntu", &ubuntu.Factory{Releases: ubuntu.Releases})
	updater.Register("alpine", driver.UpdaterSetFactoryFunc(alpine.UpdaterSet))
	updater.Register("aws", driver.UpdaterSetFactoryFunc(aws.UpdaterSet))
	updater.Register("debian", driver.UpdaterSetFactoryFunc(debian.UpdaterSet))
	updater.Register("oracle", driver.UpdaterSetFactoryFunc(oracle.UpdaterSet))
	updater.Register("photon", driver.UpdaterSetFactoryFunc(photon.UpdaterSet))
	updater.Register("pyupio", driver.UpdaterSetFactoryFunc(pyupio.UpdaterSet))
	updater.Register("suse", driver.UpdaterSetFactoryFunc(suse.UpdaterSet))
	updater.Register("rhcc", driver.UpdaterSetFactoryFunc(rhcc.UpdaterSet))

	cvssSet := driver.NewUpdaterSet()
	cvssSet.Add(&cvss.Enricher{})
	updater.Register("clair.cvss", driver.StaticSet(cvssSet))

	return nil
}
