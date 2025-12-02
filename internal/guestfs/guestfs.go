// Package guestfs ...
package guestfs

import (
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"path"
	"runtime"
	"structs"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Lib is a table of functions to call into the C guestfs library.
//
// The types are all in their "C type" reckoning. The [FS] handles these
// internally; users of this package shouldn't have to deal with the type
// nastiness.
//
// BUG(hank) This code assumes that Go's "int" and C's "int" are the
// same size. This is probably true, but is not guaranteed by spec.
//
// BUG(hank) Some of the C functions have return-via-pointer semantics for
// communicating buffer sizes. These use a C "size_t" which this code assumes
// is 64 bits, but that's not guaranteed by spec.
var lib struct {
	CreateFlags func(int) guestfs
	Launch      func(guestfs) int
	Close       func(guestfs)

	LastError        func(guestfs) string
	LastErrno        func(guestfs) int
	SetErrorHandler  func(guestfs, uintptr, unsafe.Pointer)
	PushErrorHandler func(guestfs, uintptr, unsafe.Pointer)
	PopErrorHandler  func(guestfs)

	AddDrive func(guestfs, string) int
	Mount    func(guestfs, string, string) int

	Statns   func(guestfs, string) *guestfsStatns
	Readdir  func(guestfs, string) *guestfsDirentList
	ReadFile func(guestfs, string, *uint64) *byte
	PRead    func(guestfs, string, int, int64, *uint64) *byte

	FreeStatns     func(*guestfsStatns)
	FreeDirentList func(*guestfsDirentList)
}

var loadLib = sync.OnceValue(func() error {
	// BUG(hank) This package current hard-codes attempting to dynamically load
	// "libguestfs.so.0". It's unclear what the correct library name/path is on
	// MacOS.
	handle, err := purego.Dlopen("libguestfs.so.0", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("could not open libguestfs: %w", err)
	}
	// This handle to the library is never freed, which means the library can't
	// be hot-reloaded.

	for name, fptr := range map[string]any{
		`guestfs_create`:             &lib.CreateFlags,
		`guestfs_launch`:             &lib.Launch,
		`guestfs_close`:              &lib.Close,
		`guestfs_last_error`:         &lib.LastError,
		`guestfs_last_errno`:         &lib.LastErrno,
		`guestfs_set_error_handler`:  &lib.SetErrorHandler,
		`guestfs_push_error_handler`: &lib.PushErrorHandler,
		`guestfs_pop_error_handler`:  &lib.PopErrorHandler,
		`guestfs_add_drive_ro`:       &lib.AddDrive,
		`guestfs_mount_ro`:           &lib.Mount,
		`guestfs_statns`:             &lib.Statns,
		`guestfs_readdir`:            &lib.Readdir,
		`guestfs_read_file`:          &lib.ReadFile,
		`guestfs_pread`:              &lib.PRead,
		`guestfs_free_statns`:        &lib.FreeStatns,
		`guestfs_free_dirent_list`:   &lib.FreeDirentList,
	} {
		cfn, err := purego.Dlsym(handle, name)
		if err != nil {
			return fmt.Errorf("could not open libguestfs: %w", err)
		}
		purego.RegisterFunc(fptr, cfn)
	}

	return nil
})

//revive:disable:var-naming These break Go convention and mirror C names.

type guestfs unsafe.Pointer

type guestfsDirentList struct {
	structs.HostLayout
	len uint32
	val *guestfsDirent
}

type guestfsDirent struct {
	structs.HostLayout
	ino  int64
	ftyp byte
	// Name is a C string, which isn't handled by purego in structs.
	//
	// See the [refString] and [toString] helpers.
	name *byte
}

type guestfsStatns struct {
	structs.HostLayout
	dev        int64
	ino        int64
	mode       int64
	nlink      int64
	uid        int64
	gid        int64
	rdev       int64
	size       int64
	blksize    int64
	blocks     int64
	atime_sec  int64
	atime_nsec int64
	mtime_sec  int64
	mtime_nsec int64
	ctime_sec  int64
	ctime_nsec int64
	spare      [6]int64
}

//revive:enable:var-naming

func newGuestfs() (guestfs, error) {
	//revive:disable:var-naming These break Go convention and mirror C names.
	const (
		NO_ENVIRONMENT   = (1 << 0)
		NO_CLOSE_ON_EXIT = (1 << 1)
	)
	//revive:enable:var-naming

	ptr := lib.CreateFlags(NO_ENVIRONMENT | NO_CLOSE_ON_EXIT)
	if ptr == nil {
		return nil, errors.New("unable to create guestfs handle")
	}
	// Clear the default error handler, which prints to stderr.
	lib.SetErrorHandler(ptr, uintptr(unsafe.Pointer(nil)), nil)
	return ptr, nil
}

func getError(g guestfs) error {
	errno := lib.LastErrno(g)
	if errno == 0 {
		return nil
	}
	return &guestfsErr{
		err:     syscall.Errno(errno),
		message: lib.LastError(g),
	}
}

type guestfsErr struct {
	err     error
	message string
}

func (g *guestfsErr) Error() string { return g.message }

func (g *guestfsErr) Unwrap() error { return g.err }

func addDrive(g guestfs, path string) error {
	if lib.AddDrive(g, path) != 0 {
		return getError(g)
	}
	return nil
}

func launch(g guestfs) error {
	if lib.Launch(g) != 0 {
		return getError(g)
	}
	return nil
}

func mount(g guestfs, dev, path string) error {
	if lib.Mount(g, dev, path) != 0 {
		return getError(g)
	}
	return nil
}

func pread(g guestfs, name string, dst []byte, offset int64) (int, error) {
	var read uint64
	ptr := lib.PRead(g, name, len(dst), offset, &read)
	if ptr == nil {
		return 0, getError(g)
	}
	defer libc.Free(unsafe.Pointer(ptr))
	src := unsafe.Slice(ptr, read)
	n := copy(dst, src)
	return n, nil
}

func readFile(g guestfs, name string) (*guestfsFile, error) {
	var sz uint64
	ptr := lib.ReadFile(g, name, &sz)
	if ptr == nil {
		return nil, getError(g)
	}
	data := unsafe.Slice(ptr, sz)
	f := &guestfsFile{data}
	runtime.AddCleanup(f, libc.Free, unsafe.Pointer(ptr))
	return f, nil
}

// GuestfsFile is a wrapper to hang a cleanup off of.
type guestfsFile struct {
	data []byte
}

func statns(g guestfs, name string) (*fileinfo, error) {
	p := lib.Statns(g, name)
	if p == nil {
		return nil, getError(g)
	}
	info := &fileinfo{
		name:   path.Base(name),
		statns: p,
	}
	runtime.AddCleanup(info, lib.FreeStatns, p)
	return info, nil
}

func readdir(g guestfs, p string) (iter.Seq[dirent], error) {
	l := lib.Readdir(g, p)
	if l == nil {
		return nil, getError(g)
	}
	return func(yield func(dirent) bool) {
		defer lib.FreeDirentList(l)
		for _, d := range unsafe.Slice(l.val, l.len) {
			name := toString(d.name)
			r := dirent{
				dir:  p,
				name: name,
			}
			switch d.ftyp {
			case 'b': // Block special
				r.typ = fs.ModeDevice
			case 'c': // Char special
				r.typ = fs.ModeCharDevice
			case 'd': // Directory
				r.typ = fs.ModeDir
			case 'f': // FIFO (named pipe)
				r.typ = fs.ModeNamedPipe
			case 'l': // Symbolic link
				r.typ = fs.ModeSymlink
			case 'r': // Regular file
				r.typ = 0
			case 's': // Socket
				r.typ = fs.ModeSocket
			case 'u': // Unknown file type
				r.typ = fs.ModeIrregular
			default: // aka '?': The readdir(3) call returned a d_type field with an unexpected value
				r.typ = fs.ModeIrregular
			}
			if !yield(r) {
				return
			}
		}
	}, nil
}
