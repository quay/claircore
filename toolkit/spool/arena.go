package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Arena is a directory that keeps track of its children and provides for
// cleaning them up.
type Arena struct {
	mu sync.Mutex
	m  map[interface{}]struct{}

	root string
}

// Pkg hold the initialization machinery for the package-level functions.
var pkg struct {
	Once  sync.Once
	Err   error
	Arena *Arena
}

// Setup allocates a new Arena and assigns it as the package-level default.
func setup(ctx context.Context) func() {
	return func() {
		pkg.Arena, pkg.Err = newArena(ctx, os.TempDir(), `claircore`)
		// As a special case, allow the default to exist as it's never cleaned
		// up.
		if errors.Is(pkg.Err, os.ErrExist) {
			pkg.Err = nil
		}
		// Fix up the profile to reflect where the call actually came from.
		//
		// Found the depth experimentally: sync.Once seems to add 2 frames then
		// there's the package-level function, and we want *its* caller.
		aProfile.Remove(pkg.Arena)
		aProfile.Add(pkg.Arena, 5)
	}
}

// SetDefault sets the Arena used by the package-level functions.
//
// If this function has not been called before a package-level function, a
// sensible default is used.
func SetDefault(a *Arena) {
	pkg.Once.Do(func() { pkg.Arena = a })
}

// NewArena returns a new [Arena].
//
// If "dir" is the empty string, [os.TempDir] is used.
func NewArena(ctx context.Context, dir, name string) (*Arena, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	// Don't return populated pointer from the exported function.
	a, err := newArena(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// NewArena is the inner constructor shared by NewArena and Arena.Sub.
//
// It always returns a populated *Arena.
func newArena(ctx context.Context, dir, name string) (*Arena, error) {
	a := &Arena{
		m:    make(map[interface{}]struct{}),
		root: filepath.Join(dir, name),
	}
	aProfile.Add(a, 3)
	return a, os.Mkdir(a.root, 0o750)
}

// Forget is a lock-safe map delete.
func (a *Arena) forget(v interface{}) {
	a.mu.Lock()
	delete(a.m, v)
	a.mu.Unlock()
}

// Close removes the Arena and any child [Dir], [File], and [Arena] objects that
// have been created.
func (a *Arena) Close() error { return a.close() }

// Close is effectively re-exported to make the assert simple *and* have it
// exported.
func (a *Arena) close() error {
	a.mu.Lock()
	for v := range a.m {
		c, ok := v.(interface{ close() error })
		if !ok {
			panic(fmt.Sprintf("programmer error: Arena tracking a %T", v))
		}
		c.close()
		delete(a.m, v)
	}
	a.mu.Unlock()
	os.Remove(a.root)
	aProfile.Remove(a)
	return nil
}

// Sub returns a new Arena inside the receiver Arena.
func (a *Arena) Sub(ctx context.Context, name string) (*Arena, error) {
	n, err := newArena(ctx, a.root, name)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.m[n] = struct{}{}
	a.mu.Unlock()
	return n, nil
}
