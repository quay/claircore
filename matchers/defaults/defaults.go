//
// Importing this package registers default updaters via its init function.
package defaults

import (
	"context"
	"sync"
	"time"

	"github.com/quay/claircore/crda"
	"github.com/quay/claircore/matchers/registry"
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
	registry.Register("crda", &crda.Factory{})

	return nil
}
