// Package tarfs implements the fs.FS interface over a tar archive.
package tarfs

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// FS implements a filesystem abstraction over an io.ReaderAt containing a tar.
type FS struct {
	r      io.ReaderAt
	lookup map[string]int
	inode  []inode
}

// Inode is a fake inode(7)-like structure for keeping track of filesystem
// entries.
type inode struct {
	h        *tar.Header
	children map[int]struct{}
	off, sz  int64
}

// NormPath removes relative elements. This is needed any time a name is pulled
// from the archive.
func normPath(p string) (s string) {
	s, _ = filepath.Rel("/", filepath.Join("/", p))
	return
}

// New creates an FS from the tar contained in the ReaderAt.
//
// The ReaderAt must remain valid for the entire life of the returned FS and any
// FSes returned by Sub.
func New(r io.ReaderAt) (*FS, error) {
	var err error
	s := FS{
		r:      r,
		lookup: make(map[string]int),
	}

	segs, err := findSegments(r)
	if err != nil {
		return nil, fmt.Errorf("tarfs: error finding segments: %w", err)
	}
	for _, seg := range segs {
		r := io.NewSectionReader(r, seg.start, seg.size)
		rd := tar.NewReader(r)
		i := inode{
			off: seg.start,
			sz:  seg.size,
		}
		i.h, err = rd.Next()
		if err != nil {
			return nil, fmt.Errorf("tarfs: error reading header @%d(%d): %w", seg.start, seg.size, err)
		}
		n := normPath(i.h.Name)
		switch i.h.Typeflag {
		case tar.TypeDir:
			// Has this been created this already?
			if _, ok := s.lookup[n]; ok {
				continue
			}
			i.children = make(map[int]struct{})
		case tar.TypeSymlink:
			// Fixup the linkname.
			i.h.Linkname = path.Join(path.Dir(n), i.h.Linkname)
		case tar.TypeReg:
		}
		if err := s.add(n, i); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// Add does what it says on the tin.
//
// In addition, it creates any needed leading directory elements. The caller
// should check for the existence of an "out of order" directory, as this
// function attempts to follow the POSIX spec on actions when "creating" a file
// that already exists:
// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap01.html#tagtcjh_14
func (f *FS) add(name string, ino inode) error {
	if i, ok := f.lookup[name]; ok {
		n := &f.inode[i]
		et, nt := n.h.Mode&int64(fs.ModeType), ino.h.Mode&int64(fs.ModeType)
		switch {
		case nt != 0:
			// If the new type isn't a regular file, fail.
			return fmt.Errorf("tarfs: double-add %q: new type (%x) cannot replace existing type (%x)", name, nt, et)
		case et&int64(fs.ModeDir) != 0:
			// If the existing type is a directory, fail.
			return fmt.Errorf("tarfs: double-add %q: new file cannot replace directory", name)
		}
		// Should be OK to replace now. Shadow the previous inode so we don't
		// have to renumber everything.
		f.inode[i] = ino
		return nil
	}
	i := len(f.inode)
	f.inode = append(f.inode, ino)
	f.lookup[name] = i

	n := name
	for n != "." {
		n = filepath.Dir(n)
		ti, ok := f.lookup[n]
		if !ok {
			ti = len(f.inode)
			f.inode = append(f.inode, inode{
				h: &tar.Header{
					Typeflag: tar.TypeDir,
					Name:     n,
					Mode:     int64(fs.ModeDir | 0o644),
				},
			})
			f.inode[ti].children = make(map[int]struct{})
			f.lookup[n] = ti
		}
		f.inode[ti].children[i] = struct{}{}
		i = ti
	}
	return nil
}

// GetInode returns the inode backing "name".
//
// The "op" parameter is used in error reporting.
func (f *FS) getInode(op, name string) (*inode, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	i, ok := f.lookup[name]
	if !ok {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}
	return &f.inode[i], nil
}

// Open implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	const op = `open`
	i, err := f.getInode(op, name)
	if err != nil {
		return nil, err
	}
	typ := i.h.FileInfo().Mode().Type()
	switch {
	case typ.IsRegular():
	case typ.IsDir():
		d := dir{
			h:  i.h,
			es: make([]fs.DirEntry, len(i.children)),
		}
		n := 0
		for i := range i.children {
			ct := &f.inode[i]
			d.es[n] = dirent{ct.h}
			n++
		}
		sort.Slice(d.es, sortDirent(d.es))
		return &d, nil
	case typ&fs.ModeSymlink != 0: // typ.IsSymlink()
		return f.Open(i.h.Linkname)
	default:
		// Pretend all other kinds of files don't exist.
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrExist,
		}
	}
	r := tar.NewReader(io.NewSectionReader(f.r, i.off, i.sz))
	if _, err := r.Next(); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}
	return &file{
		h: i.h,
		r: r,
	}, nil
}

// Stat implements fs.StatFS.
func (f *FS) Stat(name string) (fs.FileInfo, error) {
	// StatFS is implemented because it can avoid allocating an intermediate
	// "file" struct.
	const op = `stat`
	i, err := f.getInode(op, name)
	if err != nil {
		return nil, err
	}
	return i.h.FileInfo(), nil
}

// ReadDir implements fs.ReadDirFS.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	// ReadDirFS is implemented because it can avoid allocating an intermediate
	// "dir" struct.
	const op = `readdir`
	i, err := f.getInode(op, name)
	if err != nil {
		return nil, err
	}
	ret := make([]fs.DirEntry, 0, len(i.children))
	for ti := range i.children {
		t := &f.inode[ti]
		ret = append(ret, dirent{t.h})
	}
	sort.Slice(ret, sortDirent(ret))
	return ret, nil
}

// ReadFile implements fs.ReadFileFS.
func (f *FS) ReadFile(name string) ([]byte, error) {
	// ReadFileFS is implemented because it can avoid allocating an intermediate
	// "file" struct and can immediately allocate a byte slice of the correct
	// size.
	const op = `readfile`
	i, err := f.getInode(op, name)
	if err != nil {
		return nil, err
	}
	if i.h.FileInfo().Mode().Type()&fs.ModeSymlink != 0 {
		return f.ReadFile(i.h.Linkname)
	}
	r := tar.NewReader(io.NewSectionReader(f.r, i.off, i.sz))
	if _, err := r.Next(); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}
	ret := make([]byte, i.h.Size)
	if _, err := io.ReadFull(r, ret); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}
	return ret, nil
}

// Glob implements fs.GlobFS.
//
// See path.Match for the patten syntax.
func (f *FS) Glob(pat string) ([]string, error) {
	// GlobFS is implemented because it can avoid allocating for the walk.
	//
	// Path.Match is documented as only returning an error when the pattern is
	// invalid, so check it here and we can avoid the check in the loop.
	if _, err := path.Match(pat, ""); err != nil {
		return nil, err
	}
	var ret []string
	for n := range f.lookup {
		if ok, _ := path.Match(pat, n); ok {
			ret = append(ret, n)
		}
	}
	sort.Strings(ret)
	return ret, nil
}

// Sub implements fs.SubFS.
func (f *FS) Sub(dir string) (fs.FS, error) {
	// SubFS is implemented because it only requires a single walk and
	// conditional copy of the lookup table -- the underlying reader and inode
	// slice can be shared.
	const op = `sub`
	n, err := f.getInode(op, dir)
	if err != nil {
		return nil, err
	}
	bp := normPath(n.h.Name)
	ret := FS{
		r:      f.r,
		inode:  f.inode,
		lookup: make(map[string]int),
	}
	for n, i := range f.lookup {
		rel, err := filepath.Rel(bp, n)
		if err != nil {
			// Can't be made relative.
			continue
		}
		if strings.HasPrefix(rel, "..") {
			// Not in this subtree.
			continue
		}
		ret.lookup[rel] = i
	}
	return &ret, nil
}

// A bunch of static assertions for the fs interfaces.
var (
	_ fs.FS         = (*FS)(nil)
	_ fs.GlobFS     = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.SubFS      = (*FS)(nil)
)
