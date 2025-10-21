package guestfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type fsCache struct {
	dirent   sync.Map // map[string]*dirent
	fileinfo sync.Map // map[string]*fileinfo
	contents sync.Map // map[string]*[]byte
}

func (c *fsCache) Clear() {
	c.dirent.Clear()
	c.fileinfo.Clear()
	c.contents.Clear()
}

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
)

// FS implements [fs.FS].
type FS struct {
	g      guestfs
	closed *atomic.Bool
	cache  fsCache
}

// Open mounts the filesystem image (a file containing just a filesystem, i.e.
// no partition table) and returns an [fs.FS] implementation for examining it.
//
// The returned [*FS] may panic if not closed.
func Open(ctx context.Context, path string) (*FS, error) {
	sys := new(FS)
	if err := errors.Join(loadLibC(), loadLib()); err != nil {
		slog.DebugContext(ctx, "unable to do setup", "reason", err)
		return nil, errors.ErrUnsupported
	}

	g, err := newGuestfs()
	if err != nil {
		return nil, err
	}
	closed := new(atomic.Bool)

	// The cleanup closure holds an extra pointer to the "closed" bool, so it
	// will outlive the "sys" pointer. An atomic probably isn't strictly
	// necessary (there should only ever be two live pointers, and this one is
	// only used after the one stored in "sys" is gone), but I didn't want to
	// verify that.
	runtime.AddCleanup(sys, func(g guestfs) {
		if closed.CompareAndSwap(false, true) {
			lib.Close(g)
		}
	}, g)

	sys.g = g
	sys.closed = closed

	slog.DebugContext(ctx, "appliance launching")
	if err := addDrive(sys.g, path); err != nil {
		return nil, err
	}
	if err := launch(sys.g); err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "appliance launched")
	if err := mount(sys.g, "/dev/sda", "/"); err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "fs mounted")

	return sys, nil
}

// Close releases held resources.
//
// Any [fs.File]s returned by the receiver should not be used after this method
// is called.
func (sys *FS) Close() error {
	// Eagerly deref pointers in the caches.
	sys.cache.Clear()
	if sys.closed.CompareAndSwap(false, true) {
		lib.Close(sys.g)
	}
	return nil
}

// ToAbs translates a name from [fs.FS] convention (always relative to the root)
// to the guestfs convention (always absolute).
func toAbs(name string) string {
	return "/" + path.Clean(name)
}

// All the various fs method implementation are implemented as an exported
// version that expects [fs.FS] paths and an unexported version that expects
// guestfs (absolute) paths. The convention to follow is:
//   - File names are called "name".
//   - Paths in structs are guestfs paths, called "path".

// Open implements [fs.FS].
func (sys *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}

	return sys.open(toAbs(name))
}

func (sys *FS) open(path string) (fs.File, error) {
	stat, err := sys.stat(path)
	if err != nil {
		return nil, err
	}

	return &file{
		sys:  sys,
		stat: stat,
		path: path,
	}, nil
}

var (
	_ fs.File        = (*file)(nil)
	_ fs.ReadDirFile = (*file)(nil)
	_ io.Reader      = (*file)(nil)
	_ io.ReaderAt    = (*file)(nil)
)

// File is the struct backing returned [fs.File]s.
//
// If [Read] is called, the file contents are pulled into memory in their
// entirety.
type file struct {
	sys      *FS
	stat     fs.FileInfo
	path     string
	contents *guestfsFile
	reader   *bytes.Reader
	dirents  []fs.DirEntry
}

// Close implements [fs.File].
func (f *file) Close() error {
	*f = file{}
	return nil
}

// Stat implements [fs.File].
func (f *file) Stat() (fs.FileInfo, error) { return f.stat, nil }

// ReadDir implements [fs.ReadDirFile].
//
// BUG(hank) ReadDir currently does not respect the "n" argument and always
// returns the entire directory contents.
func (f *file) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.dirents == nil {
		var err error
		f.dirents, err = f.sys.readDir(f.path)
		if err != nil {
			return nil, err
		}
	}
	var r []fs.DirEntry
	if n <= 0 {
		r, f.dirents = f.dirents, f.dirents[len(f.dirents):]
	} else {
		i := min(n, len(f.dirents))
		r, f.dirents = f.dirents[:i], f.dirents[i:]
	}
	return r, nil
}

// Read implements [io.Reader].
//
// Calling Read pulls the entire file contents into memory.
func (f *file) Read(b []byte) (int, error) {
	if f.reader == nil {
		name := f.path
		cache := &f.sys.cache.contents
		v, loaded := cache.Load(name)
		if !loaded {
			rd, err := readFile(f.sys.g, name)
			if err != nil {
				return 0, err
			}
			v, _ = cache.LoadOrStore(name, rd)
		}
		f.contents = v.(*guestfsFile)
		f.reader = bytes.NewReader(f.contents.data)
	}
	return f.reader.Read(b)
}

// ReadAt implements [io.ReaderAt].
//
// BUG(hank) The underlying [guestfs_pread(3)] call used for the [io.ReaderAt]
// implementation is only more efficient (due to calling convention switch and
// buffer copies) if the data is actually being processed piece-wise and large
// buffers (e.g. 2 MiB) are used.
//
// [guestfs_pread(3)]: https://libguestfs.org/guestfs.3.html#guestfs_pread
func (f *file) ReadAt(b []byte, offset int64) (int, error) {
	if f.reader == nil {
		return pread(f.sys.g, f.path, b, offset)
	}
	return f.reader.ReadAt(b, offset)
}

// Stat implements [fs.StatFS].
func (sys *FS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	return sys.stat(toAbs(name))
}

func (sys *FS) stat(path string) (fs.FileInfo, error) {
	v, loaded := sys.cache.fileinfo.Load(path)
	if !loaded {
		fi, err := statns(sys.g, path)
		if err != nil {
			return nil, err
		}
		fi.sys = sys
		v, _ = sys.cache.fileinfo.LoadOrStore(path, fi)
	}
	return v.(*fileinfo), nil
}

type fileinfo struct {
	sys    *FS
	path   string
	statns *guestfsStatns
}

// IsDir implements [fs.FileInfo].
func (f *fileinfo) IsDir() bool {
	//revive:disable:var-naming This breaks Go convention to mirror the C name.
	const S_IFDIR = 0o040000
	//revive:enable:var-naming
	return (f.statns.mode & S_IFDIR) != 0
}

// ModTime implements [fs.FileInfo].
func (f *fileinfo) ModTime() time.Time {
	return time.Unix(f.statns.mtime_sec, f.statns.mtime_nsec)
}

// Mode implements [fs.FileInfo].
func (f *fileinfo) Mode() fs.FileMode {
	//revive:disable:var-naming These break Go convention and mirror C names.
	const (
		S_IFSOCK = 0o140000 // socket
		S_IFLNK  = 0o120000 // symbolic link
		S_IFREG  = 0o100000 // regular file
		S_IFBLK  = 0o060000 // block device
		S_IFDIR  = 0o040000 // directory
		S_IFCHR  = 0o020000 // character device
		S_IFIFO  = 0o010000 // FIFO
	)
	//revive:enable:var-naming

	m := f.statns.mode
	fm := fs.FileMode(m & 0o7777) // Last 12 bits are the same.
	// Translate the relevant Linux mode bits:
	for _, b := range []struct {
		Test int64
		Flag fs.FileMode
	}{
		{S_IFSOCK, fs.ModeSocket},
		{S_IFLNK, fs.ModeSymlink},
		{S_IFBLK, fs.ModeDevice},
		{S_IFDIR, fs.ModeDir},
		{S_IFCHR, fs.ModeCharDevice},
		{S_IFIFO, fs.ModeNamedPipe},
	} {
		if m&b.Test != 0 {
			fm |= b.Flag
		}
	}
	return fm
}

// Name implements [fs.FileInfo].
func (f *fileinfo) Name() string { return path.Base(f.path) }

// Size implements [fs.FileInfo].
func (f *fileinfo) Size() int64 { return f.statns.size }

// Sys implements [fs.FileInfo].
func (f *fileinfo) Sys() any { return f.statns }

// ReadDir implements [fs.ReadDirFS].
func (sys *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	return sys.readDir(toAbs(name))
}

func (sys *FS) readDir(name string) ([]fs.DirEntry, error) {
	l := lib.Readdir(sys.g, name)
	if l == nil {
		return nil, getError(sys.g)
	}
	defer lib.FreeDirentList(l)
	raws := unsafe.Slice(l.val, l.len)
	ents := make([]dirent, len(raws))
	ret := make([]fs.DirEntry, len(raws))

	for i := range raws {
		raw := &raws[i]
		ent := &ents[i]
		ent.sys = sys
		ent.dir = name
		ent.name = toString(raw.name)
		switch raw.ftyp {
		case 'b': // Block special
			ent.typ = fs.ModeDevice
		case 'c': // Char special
			ent.typ = fs.ModeCharDevice
		case 'd': // Directory
			ent.typ = fs.ModeDir
		case 'f': // FIFO (named pipe)
			ent.typ = fs.ModeNamedPipe
		case 'l': // Symbolic link
			ent.typ = fs.ModeSymlink
		case 'r': // Regular file
			ent.typ = 0
		case 's': // Socket
			ent.typ = fs.ModeSocket
		case 'u': // Unknown file type
			ent.typ = fs.ModeIrregular
		default: // aka '?': The readdir(3) call returned a d_type field with an unexpected value
			ent.typ = fs.ModeIrregular
		}
		ret[i] = ent
	}

	// TODO(hank): Cache ReadDir calls.
	slices.SortFunc(ret, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return ret, nil
}

var _ fs.DirEntry = (*dirent)(nil)

type dirent struct {
	sys  *FS
	dir  string
	name string
	typ  fs.FileMode
}

// Info implements [fs.DirEntry].
func (d *dirent) Info() (fs.FileInfo, error) {
	return d.sys.stat(path.Join(d.dir, d.name))
}

// IsDir implements [fs.DirEntry].
func (d *dirent) IsDir() bool { return d.typ == fs.ModeDir }

// Name implements [fs.DirEntry].
func (d *dirent) Name() string { return d.name }

// Type implements [fs.DirEntry].
func (d *dirent) Type() fs.FileMode { return d.typ }

// ReadFile implements [fs.ReadFileFS].
func (sys *FS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	return sys.readFile(toAbs(name))
}

func (sys *FS) readFile(name string) ([]byte, error) {
	// If the [foreign pointer tracking proposal] makes it, then this method
	// could avoid a copy and just hand out the foreign-backed slice.
	//
	// [foreign pointer tracking proposal]: https://github.com/golang/go/issues/70224
	v, loaded := sys.cache.contents.Load(name)
	if !loaded {
		rd, err := readFile(sys.g, name)
		if err != nil {
			return nil, err
		}
		v, _ = sys.cache.contents.LoadOrStore(name, rd)
	}
	f := v.(*guestfsFile)
	b := make([]byte, len(f.data))
	copy(b, f.data)
	return b, nil
}
