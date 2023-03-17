package spool

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NewFile returns a new [File] allocated in the [Default] arena.
//
// See also [Arena.NewFile].
func NewFile(ctx context.Context, name string) (*File, error) {
	pkg.Once.Do(setup(ctx))
	if pkg.Err != nil {
		return nil, pkg.Err
	}
	return pkg.Arena.newFile(ctx, name)
}

// NewSpool returns a new, unlinked [File] allocated in the [Default] arena.
//
// See also [Arena.NewSpool].
func NewSpool(ctx context.Context, name string) (*File, error) {
	pkg.Once.Do(setup(ctx))
	if pkg.Err != nil {
		return nil, pkg.Err
	}
	f, err := pkg.Arena.newFile(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// NewFile opens a File inside the Arena.
//
// The passed "name" has the same pattern rules as [os.CreateTemp] if it
// contains an "*".
func (a *Arena) NewFile(ctx context.Context, name string) (*File, error) {
	return a.newFile(ctx, name)
}

// NewSpool opens an unlinked File inside the Arena.
//
// The passed "name" has the same patten rules as [os.CreateTemp].
// An unlinked file is useful to ensure the file is cleaned up if the process
// meets an untimely demise. The trade-off is that the file is harder to share
// with other processes.
func (a *Arena) NewSpool(ctx context.Context, name string) (*File, error) {
	f, err := a.newFile(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// NewFile is the common File allocation routines. It's split this way to make the
// profile frame count correct.
func (a *Arena) newFile(ctx context.Context, name string) (*File, error) {
	var err error
	f := &File{
		arena: a,
	}
	if strings.Contains(name, "*") {
		f.File, err = os.CreateTemp(a.root, name)
	} else {
		f.File, err = os.OpenFile(filepath.Join(a.root, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	}
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.m[f] = struct{}{}
	a.mu.Unlock()
	fProfile.Add(f, 3)
	return f, nil
}

// File is a file opened inside an Arena.
type File struct {
	*os.File
	arena *Arena
	ro    *os.File // Is this a re-opened file?
}

// Close removes the File.
func (f *File) Close() error {
	// Close removes the File from the Arena, which requires a lock.
	// It's split this way to allow the Arena to remove the File while holding
	// its own lock.
	f.arena.forget(f)
	return f.close()
}

// Close removes the on-disk file and removes the profile entry.
func (f *File) close() error {
	os.Remove(f.Name()) // May already be unlinked, so ignore error.
	f.File.Close()
	if f.ro != nil {
		// "Ro" files only come from re-opening via proc, so don't bother with
		// the Remove call.
		f.ro.Close()
	}
	fProfile.Remove(f)
	return nil
}

// Reopen opens a new [File] pointing to the same backing [os.File].
//
// Unlike a file descriptor returned by dup(2), this returned file is an
// independent file description of the same file. The returned [File] is tracked
// by the same [Arena] as the receiver [File] and has the same [File.Close] and
// [Arena.Close] semantics.
func (f *File) Reopen() (*File, error) {
	// This should be fine to do from any File, even if the receiver has been
	// reopened itself.
	ro, err := os.Open(filepath.Join("/proc/self/fd", strconv.Itoa(int(f.Fd()))))
	if err != nil {
		return nil, err
	}
	// Doing it this way keeps the name correct, at the cost of an extra live
	// os.File object. The "ro" member owns the file descriptor, and the exposed
	// file object uses it with the desired name.
	//
	// The os.File being embedded means the File implements all the common io
	// interfaces, but has the downside that a caller could call the "real"
	// Close method directly.
	n := &File{
		File:  os.NewFile(ro.Fd(), f.Name()),
		arena: f.arena,
		ro:    ro,
	}
	n.arena.mu.Lock()
	n.arena.m[n] = struct{}{}
	n.arena.mu.Unlock()
	fProfile.Add(n, 2)
	return n, nil
}
