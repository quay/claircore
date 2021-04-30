// Package updater holds a registry of default updaters.
//
// A set of in-tree updaters can be added by using the defaults package's Set
// function.
package updater

import (
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
