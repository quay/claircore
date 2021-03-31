// Package matchers holds a registry of default matchers.
package registry

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
	fs map[string]driver.MatcherFactory
}{
	fs: make(map[string]driver.MatcherFactory),
}

// Register registers an MatcherFactory.
//
// Register will panic if the same name is used twice.
func Register(name string, f driver.MatcherFactory) {
	pkg.Lock()
	defer pkg.Unlock()
	if _, ok := pkg.fs[name]; ok {
		panic("")
	}
	pkg.fs[name] = f
}

// Registered returns a new map populated with the registered MatcherFactories.
func Registered() map[string]driver.MatcherFactory {
	pkg.Lock()
	defer pkg.Unlock()
	r := make(map[string]driver.MatcherFactory, len(pkg.fs))
	for k, v := range pkg.fs {
		r[k] = v
	}
	return r
}

// Configure calls the Configure method on all the passed-in
// MatcherFactories.
func Configure(ctx context.Context, fs map[string]driver.MatcherFactory, cfg map[string]driver.MatcherConfigUnmarshaler, c *http.Client) error {
	if c == nil {
		return errors.New("invalid *http.Client")
	}

	errd := false
	var b strings.Builder
	b.WriteString("matchers: errors configuring factories:")

	for name, fac := range fs {
		f, fOK := fac.(driver.MatcherConfigurable)
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
