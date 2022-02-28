package updater

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

var pkg = struct {
	sync.Mutex
	fs map[string]driver.UpdaterSetFactory
}{
	fs: make(map[string]driver.UpdaterSetFactory),
}

// Register registers an UpdaterSetFactory.
//
// Register will panic if the same name is used twice.
//
// Deprecated: See [Updater].
func Register(name string, f driver.UpdaterSetFactory) {
	pkg.Lock()
	defer pkg.Unlock()
	if _, ok := pkg.fs[name]; ok {
		panic("")
	}
	pkg.fs[name] = f
}

// Registered returns a new map populated with the registered UpdaterSetFactories.
//
// Deprecated: See [Updater].
func Registered() map[string]driver.UpdaterSetFactory {
	pkg.Lock()
	defer pkg.Unlock()
	r := make(map[string]driver.UpdaterSetFactory, len(pkg.fs))
	for k, v := range pkg.fs {
		r[k] = v
	}
	return r
}

// Configure calls the Configure method on all the passed-in
// UpdaterSetFactories.
//
// Deprecated: See [Updater].
func Configure(ctx context.Context, fs map[string]driver.UpdaterSetFactory, cfg map[string]driver.ConfigUnmarshaler, c *http.Client) error {
	if c == nil {
		return errors.New("passed invalid *http.Client")
	}
	errd := false
	var b strings.Builder
	b.WriteString("updater: errors configuring factories:")

	for name, fac := range fs {
		ev := zlog.Debug(ctx).
			Str("factory", name)
		f, ok := fac.(driver.Configurable)
		if ok {
			ev.Msg("configuring factory")
			cf := cfg[name]
			if cf == nil {
				cf = noopConfig
			}
			if err := f.Configure(ctx, cf, c); err != nil {
				errd = true
				b.WriteString("\n\t")
				b.WriteString(err.Error())
			}
		} else {
			ev.Msg("factory unconfigurable")
		}
	}

	if errd {
		return errors.New(b.String())
	}
	return nil
}

// NoopConfig is used when an explicit config is not provided.
func noopConfig(_ interface{}) error { return nil }
