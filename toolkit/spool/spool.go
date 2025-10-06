// Package spool provides utilities for managing "spool files".
//
// Files returned by this package can be counted on to be removed when all open descriptors are closed.
package spool

import (
	"cmp"
	"io/fs"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
)

// Root is the location all the spool files go into.
//
// This is initialized in os-specific files.
var root *os.Root

// Mkname generates a unique file name based on the provided prefix.
func mkname(prefix string) string {
	return cmp.Or(prefix, "tmp") + "." +
		strconv.FormatUint(uint64(rand.Uint32()), 10)
}

// OpenFile opens a temporary file with the provided prefix.
//
// If "prefix" is not provided, "tmp" will be used.
// Returned files cannot be opened by path. Callers should use [Reopen].
func OpenFile(prefix string, flag int, perm fs.FileMode) (*os.File, error) {
	name := osAdjustName(mkname(prefix))
	flag = osAdjustFlag(flag)
	f, err := root.OpenFile(name, flag, perm)
	if f != nil {
		osAddCleanup(f)
	}
	return f, err
}

// Create returns an [*os.File] that cannot be opened by path and will be
// removed when closed.
func Create() (*os.File, error) {
	return OpenFile("", os.O_CREATE|os.O_RDWR, 0o600)
}

// Mkdir creates a directory with the provided prefix.
//
// The directory will have its contents removed when the returned [*os.Root] is
// garbage collected.
func Mkdir(prefix string, perm fs.FileMode) (*os.Root, error) {
	name := mkname(prefix)
	if err := root.Mkdir(name, perm); err != nil {
		return nil, err
	}
	r, err := root.OpenRoot(name)
	if err == nil { // NB If successful
		runtime.AddCleanup(r, func(name string) {
			root.RemoveAll(name)
		}, name)
	}
	return r, err
}

/*
This package needs a few parts implemented in OS-specific ways.
Below is a quick rundown of them, along with a ready-to-use documentation comment.

# Exported

The documentation for these implementations should add additional paragraphs explaining the OS-specific parts starting "The ${OS} implementation [...]".

See the Linux implementations in os_linux.go for an example.

	// Reopen provides or emulates re-opening a file and obtaining an independent file description.
	func Reopen(f *os.File, flag int) (*os.File, error)

The [Reopen] API is not possible with dup(2), which returns another file descriptor to the same file description.
An implementation using dup(2) would not provide independent offsets.

# Unexported

	osAdjustName(string) string

AdjustName should modify the passed file name as needed and return the result.

	osAdjustFlag(int) int

AdjustFlag should modify the passed flags as needed and return the result.

	osAddCleanup(*os.File)

AddCleanup should use [runtime.AddCleanup] to attach any needed cleanup functions to the passed [*os.File].
An implementation will not be called with a nil pointer.
*/
