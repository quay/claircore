package spool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// NewDir returns a new [Dir] allocated in the [Default] arena.
//
// See also [Arena.NewDir].
func NewDir(ctx context.Context, name string) (*Dir, error) {
	pkg.Once.Do(setup(ctx))
	if pkg.Err != nil {
		return nil, pkg.Err
	}
	return pkg.Arena.newDir(ctx, name)
}

// NewDir returns a Dir allocated inside the Arena.
//
// The passed "name" has the same pattern rules as [os.MkdirTemp] if it contains
// an "*".
func (a *Arena) NewDir(ctx context.Context, name string) (*Dir, error) {
	return a.newDir(ctx, name)
}

// NewDir is the common Dir allocation routines. It's split this way to make the
// profile frame count correct.
func (a *Arena) newDir(ctx context.Context, name string) (*Dir, error) {
	d := &Dir{arena: a}
	var err error
	if strings.Contains(name, "*") {
		d.name, err = os.MkdirTemp(a.root, name)
	} else {
		d.name = filepath.Join(a.root, name)
		err = os.Mkdir(d.name, 0o700)
	}
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.m[d] = struct{}{}
	a.mu.Unlock()
	dProfile.Add(d, 3)
	return d, nil
}

// Dir is a directory created inside of an arena.
//
// The name of the directory should be discovered by the Name method, in case
// there was a pattern in use in the name passed to NewDir.
type Dir struct {
	arena *Arena
	name  string
}

// Name reports the directory name.
func (d *Dir) Name() string {
	return d.name
}

// Close removes the Dir.
func (d *Dir) Close() error {
	// Close removes the Dir from the Arena, which requires a lock.
	// It's split this way to allow the Arena to remove the Dir while holding
	// its own lock.
	d.arena.forget(d)
	return d.close()
}

// Close removes the on-disk directory and removes the profile entry.
func (d *Dir) close() error {
	dProfile.Remove(d)
	return os.RemoveAll(d.name)
}
