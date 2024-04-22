// Package tarfs implements the fs.FS interface over a tar archive.
package tarfs

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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

// NormPath removes relative elements and enforces that the resulting string is
// utf8-clean.
//
// This is needed any time a name is pulled from the archive.
func normPath(p string) string {
	// This is OK because [path.Join] is documented to call [path.Clean], which
	// will remove any parent ("..") elements, and will always return a string
	// of at least length 1, because the static component is length 1.
	s := path.Join("/", p)[1:]
	if len(s) == 0 {
		return "."
	}
	if utf8.ValidString(s) {
		return s
	}
	// Slow path -- need to decode the string an write out escapes.
	// This is roughly modeled on [strings.ToValidUTF8], but without the run
	// coalescing and the replacement is based on the invalid byte sequence. The
	// [strings.ToValidUTF8] function only cares if the encoding is valid, not
	// if it's a valid codepoint.
	var b strings.Builder
	b.Grow(len(s) + 3) // We already know we'll need at least one replacement, which are 4 bytes.
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			b.WriteByte(c)
			continue
		}
		// May be a valid multibyte rune.
		r, w := utf8.DecodeRuneInString(s[i:])
		if r != utf8.RuneError {
			i += w
			b.WriteRune(r)
			continue
		}
		for n := 0; n < w; n++ {
			c := uint8(s[i+n])
			b.WriteString(`\x`)
			b.WriteString(strconv.FormatUint(uint64(c), 16))
		}
		i += w
	}
	return b.String()
}

func newDir(n string) inode {
	return inode{
		h: &tar.Header{
			Typeflag: tar.TypeDir,
			Name:     n,
			Mode:     int64(fs.ModeDir | 0o644),
		},
		children: make(map[int]struct{}),
	}
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
	hardlink := make(map[string][]string)
	if err := s.add(".", newDir("."), hardlink); err != nil {
		return nil, err
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
		i.h.Name = normPath(i.h.Name)
		n := i.h.Name
		switch i.h.Typeflag {
		case tar.TypeDir:
			// Has this been created this already?
			if _, ok := s.lookup[n]; ok {
				continue
			}
			i.children = make(map[int]struct{})
		case tar.TypeSymlink, tar.TypeLink:
			// If an absolute path, norm the path and it should be fine.
			// A symlink could dangle, but that's really weird.
			if path.IsAbs(i.h.Linkname) {
				i.h.Linkname = normPath(i.h.Linkname)
				break
			}
			if i.h.Typeflag == tar.TypeSymlink {
				// Assume that symlinks are relative to the directory they're
				// present in.
				i.h.Linkname = path.Join(path.Dir(n), i.h.Linkname)
			}
			i.h.Linkname = normPath(i.h.Linkname)
			// Linkname should now be a full path from the root of the tar.
		case tar.TypeReg:
		}
		if err := s.add(n, i, hardlink); err != nil {
			return nil, err
		}
	}
	// Cleanup any dangling hardlinks.
	// This leaves them in the inode slice, but removes them from the observable
	// tree.
	for _, rms := range hardlink {
		for _, rm := range rms {
			idx := s.lookup[rm]
			delete(s.lookup, rm)
			p := s.inode[s.lookup[path.Dir(rm)]]
			delete(p.children, idx)
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
//
// The "hardlink" map is used for deferring hardlink creation.
func (f *FS) add(name string, ino inode, hardlink map[string][]string) error {
	const op = `create`
Again:
	if i, ok := f.lookup[name]; ok {
		n := &f.inode[i]
		et, nt := n.h.FileInfo().Mode()&fs.ModeType, ino.h.FileInfo().Mode()&fs.ModeType
		switch {
		case nt != 0:
			// If the new type isn't a regular file, fail.
			return &fs.PathError{
				Op:   op,
				Path: name,
				Err:  fmt.Errorf("new type (%x) cannot replace existing type (%x): %w", nt, et, fs.ErrExist),
			}
		case et&fs.ModeDir != 0:
			// If the existing type is a directory, fail.
			return &fs.PathError{
				Op:   op,
				Path: name,
				Err:  fmt.Errorf("new file cannot replace directory: %w", fs.ErrExist),
			}
		case et&fs.ModeSymlink != 0:
			// Follow the link target.
			name = n.h.Linkname
			goto Again
		}
		// Should be OK to replace now. Shadow the previous inode so we don't
		// have to renumber everything.
		f.inode[i] = ino
		return nil
	}

	// Hardlink handling: if the target doesn't exist yet, make a note in passed-in map.
	if ino.h.Typeflag == tar.TypeLink {
		tgt := ino.h.Linkname
		if _, ok := f.lookup[tgt]; !ok {
			hardlink[tgt] = append(hardlink[tgt], name)
		}
	}
	delete(hardlink, name)
	i := len(f.inode)
	f.inode = append(f.inode, ino)
	f.lookup[name] = i

	cycle := make(map[*inode]struct{})
	dir := path.Dir(name)
AddEnt:
	switch dir {
	case name:
		// Skip
	case ".":
		// Add was called with a root entry, like "a" -- make sure to link this to the root directory.
		root := &f.inode[f.lookup["."]]
		root.children[i] = struct{}{}
	default:
		parent, err := f.getInode(op, dir)
		if err != nil {
			parent, err = f.walkTo(dir, true)
		}
		if err != nil {
			return err
		}
		if _, ok := cycle[parent]; ok {
			return &fs.PathError{
				Op:   op,
				Path: dir,
				Err:  fmt.Errorf("found cycle when resolving member: %w", fs.ErrInvalid),
			}
		}
		cycle[parent] = struct{}{}
		switch parent.h.Typeflag {
		case tar.TypeDir:
			// OK
		case tar.TypeLink:
			// This is annoying -- hard linking to directories is weird
			fallthrough
		case tar.TypeSymlink:
			dir = parent.h.Linkname
			goto AddEnt
		default:
			return &fs.PathError{
				Op:   op,
				Path: parent.h.Name,
				Err:  fmt.Errorf("error while connecting child %q: %w", name, fs.ErrExist),
			}
		}
		parent.children[i] = struct{}{}
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
	name = path.Clean(name)
	if i, ok := f.lookup[name]; ok {
		return &f.inode[i], nil
	}

	i, err := f.walkTo(name, false)
	if err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}
	return i, nil
}

// WalkTo does a walk from the root as far along the provided path as possible,
// resolving symlinks as necesarry. If any segments are missing (including the final
// segments), they are created as directories if the "create" bool is passed.
func (f *FS) walkTo(p string, create bool) (*inode, error) {
	w := strings.Split(p, "/")
	var cur *inode
	var b strings.Builder

	cur = &f.inode[f.lookup["."]]
	i := 0
	for lim := len(w); i < lim; i++ {
		n := w[i]
		if i != 0 {
			b.WriteByte('/')
		}
		b.WriteString(n)
		var child *inode
		var found bool
		for ci := range cur.children {
			child = &f.inode[ci]
			cn := path.Base(child.h.Name)
			if cn != n {
				continue
			}
			cycle := make(map[int]struct{})
		Resolve:
			for {
				if _, ok := cycle[ci]; ok {
					return nil, &fs.PathError{
						Op:   `walk`,
						Path: b.String(),
						Err:  fmt.Errorf("found cycle when resolving member: %w", fs.ErrInvalid),
					}
				}
				cycle[ci] = struct{}{}
				switch child.h.Typeflag {
				case tar.TypeDir:
					break Resolve
				case tar.TypeSymlink:
					tgt := child.h.Linkname
					var ok bool
					ci, ok = f.lookup[tgt]
					switch {
					case ok && create, ok && !create:
						child = &f.inode[ci]
						break Resolve
					case !ok && create:
						f.add(tgt, newDir(tgt), nil)
						ci = f.lookup[tgt]
						child = &f.inode[ci]
					case !ok && !create:
						return nil, fmt.Errorf("tarfs: walk to %q, but missing segment %q", p, n)
					}
				case tar.TypeReg:
					if i == (lim - 1) {
						break Resolve
					}
					return nil, &fs.PathError{
						Op:   `walk`,
						Path: p,
						Err:  fmt.Errorf("found symlink to regular file while connecting child %q: %w", b.String(), fs.ErrExist),
					}
				}
			}
			found = true
			break
		}
		switch {
		case found && create, found && !create:
			// OK
		case !found && create:
			fp := b.String() // Make sure to use the full path and not just the member name.
			f.add(fp, newDir(n), nil)
			ci := f.lookup[fp]
			child = &f.inode[ci]
		case !found && !create:
			return nil, fmt.Errorf("tarfs: walk to %q, but missing segment %q", p, b.String())
		}
		cur = child
	}
	return cur, nil
}

// Open implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	const op = `open`
	i, err := f.getInode(op, name)
	if err != nil {
		return nil, err
	}
	typ := i.h.FileInfo().Mode().Type()
	var r *tar.Reader
	switch {
	case typ.IsRegular() && i.h.Typeflag != tar.TypeLink:
		r = tar.NewReader(io.NewSectionReader(f.r, i.off, i.sz))
	case typ.IsRegular() && i.h.Typeflag == tar.TypeLink:
		tgt, err := f.getInode(op, i.h.Linkname)
		if err != nil {
			return nil, err
		}
		r = tar.NewReader(io.NewSectionReader(f.r, tgt.off, tgt.sz))
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
	bp := n.h.Name
	ret := FS{
		r:      f.r,
		inode:  f.inode,
		lookup: make(map[string]int),
	}
	for n, i := range f.lookup {
		if !strings.HasPrefix(n, bp) {
			// Not in this subtree.
			continue
		}
		// NormPath handles the root condition cleanly.
		rel := normPath(strings.TrimPrefix(n, bp))
		ret.lookup[rel] = i
	}
	return &ret, nil
}

// A bunch of static assertions for the fs interfaces.
var (
	_ fs.FS        = (*FS)(nil)
	_ fs.GlobFS    = (*FS)(nil)
	_ fs.ReadDirFS = (*FS)(nil)
	_ fs.StatFS    = (*FS)(nil)
	_ fs.SubFS     = (*FS)(nil)
)
