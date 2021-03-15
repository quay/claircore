// Importing this package registers default matchers via its init function.
package defaults

import (
	"context"
	"sync"
	"time"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/crda"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/matchers/registry"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
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
// matchers.
func Error() error {
	return regerr
}

// defaultMatchers is a variable containing
// all the matchers libvuln will use to match
// index records to vulnerabilities.
var defaultMatchers = []driver.Matcher{
	&alpine.Matcher{},
	&aws.Matcher{},
	&debian.Matcher{},
	&oracle.Matcher{},
	&photon.Matcher{},
	&python.Matcher{},
	&rhel.Matcher{},
	&suse.Matcher{},
	&ubuntu.Matcher{},
}

func inner(ctx context.Context) error {
	registry.Register("crda", &crda.Factory{})

	for _, m := range defaultMatchers {
		mf := driver.MatcherStatic(m)
		registry.Register(m.Name(), mf)
	}

	return nil
}
