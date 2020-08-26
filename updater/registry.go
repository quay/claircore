// Package updater holds a registry of default updaters.
//
// A set of in-tree updaters can be added by using the defaults package's Set
// function.
package updater

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

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
func Register(name string, f driver.UpdaterSetFactory) {
	pkg.Lock()
	defer pkg.Unlock()
	if _, ok := pkg.fs[name]; ok {
		panic("")
	}
	pkg.fs[name] = f
}

// Registered returns a new map populated with the registered UpdaterSetFactories.
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
func Configure(ctx context.Context, fs map[string]driver.UpdaterSetFactory, cfg map[string]driver.ConfigUnmarshaler, c *http.Client) error {
	errd := false
	var b strings.Builder
	b.WriteString("updater: errors configuring factories:")
	if c == nil {
		c = http.DefaultClient
	}

	for name, fac := range fs {
		f, fOK := fac.(driver.Configurable)
		cf, cfOK := cfg[name]
		if fOK && cfOK {
			if err := f.Configure(ctx, cf, c); err != nil {
				errd = true
				b.WriteString("\n\t")
				b.WriteString(err.Error())
			}
		}
	}

	if errd {
		return errors.New(b.String())
	}
	return nil
}
