package tarfs

import (
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Srv is the struct handling all the mapping for file data.
//
// I couldn't think of a good name for this, so "server" because it serves file data.
// This is meant to be embedded, then filled in with hooks depending on the format that's being read out of the backing reader.
//
// This whole dance is complicated, because we have subtly different data flows that we want to abstract away:
//   - block-based "dumb" data requests
//   - whole-file requests.
//
// We also need to optionally do decompresison which means in the dumb case, there's no knowing where block boundaries actually lie.
type srv struct {
	// Open is a hook function that's called once for every regular file in
	// order for the embedding struct to make file data available in "r" and
	// report the offset and size.
	open openFunc
	// Raw contains uncompressed, ready-to-read file data.
	raw io.ReaderAt
	// Lookup is a map of strings to indexes in the following slices.
	lookup map[string]int
	// Mu guards the following members.
	// This is only used once the object is fully initialized.
	mu sync.RWMutex
	// Initd is a bitset tracking initialized meta elements.
	initd big.Int
	// The following slices are file metadata, split into externally-visible and
	// internal-only components.
	entry []Entry
	meta  []meta
}

// Interface assertions for srv.
var (
	_ fs.FS         = (*srv)(nil)
	_ fs.GlobFS     = (*srv)(nil)
	_ fs.ReadDirFS  = (*srv)(nil)
	_ fs.ReadFileFS = (*srv)(nil)
	_ fs.StatFS     = (*srv)(nil)
	// Skipped implementing [fs.SubFS], as sharing the backing buffer would be complicated.
)

// OpenFunc is the hook for embedders of srv to make data ready in the ReaderAt and report the size and offset.
type openFunc func(inode) (offset, size int64, err error)

// Inode is a fake inode(7)-like structure for keeping track of filesystem entries.
//
// Inode implements [fs.FileInfo].
//
// Inode ties together the immutable [Entry] and the internal book-keeping [meta] structs.
// Any given inode is not unique, but the structs pointed to are unique and are shared.
type inode struct {
	*Entry
	*meta
	// N is the index data is kept at in the parent srv's members.
	N int
}

// Interface assertion for inode.
var _ fs.FileInfo = (*inode)(nil)

// Name implements [fs.FileInfo].
func (i *inode) Name() string { return path.Base(i.Entry.Name) }

// Size implements [fs.FileInfo].
func (i *inode) Size() int64 { return int64(i.Entry.Size) }

// Mode implements [fs.FileInfo].
func (i *inode) Mode() fs.FileMode { return fs.FileMode(i.Entry.Mode) }

// ModTime implements [fs.FileInfo].
func (i *inode) ModTime() time.Time { return i.Entry.ModTime }

// IsDir implements [fs.FileInfo].
func (i *inode) IsDir() bool { return i.Type == typeDir }

// Sys implements [fs.FileInfo].
func (i *inode) Sys() interface{} { return i.Entry }

// Meta is internal book-keeping for file entries.
//
// This is kept alongside the entries to cut-down on duplication between the external [Entry] type and an internal type that would have the same information along with book-keeping fields.
type meta struct {
	children map[int]struct{}
	chunk    []int
	off, sz  int64
}

// Init initializes the srv.
func (s *srv) init(r io.ReaderAt, es []Entry, open openFunc) error {
	sz := len(es) + 1
	s.lookup = make(map[string]int, sz)
	s.entry = make([]Entry, 0, sz)
	s.meta = make([]meta, 0, sz)
	s.initd.SetUint64(0)
	s.initd.SetBit(&s.initd, sz, 0)
	s.raw = r
	s.open = open

	links := make(map[string][]string)
	// Mkdir the root:
	const root = `.`
	i := len(s.entry)
	s.entry = append(s.entry, newEntryDir(root))
	s.meta = append(s.meta, meta{
		children: make(map[int]struct{}),
	})
	s.lookup[root] = i
	// This loop needs to copy the Entries, because we may need to create entries.
	// That shouldn't happen in the seekable variants but *does* happen in normal tars.
	for _, e := range es {
		e.Name = normPath(e.Name) // Normpath for good measure.
		switch e.Type {
		case typeDir:
			// Hack to avoid going into the whole add path.
			if _, ok := s.lookup[e.Name]; ok {
				continue
			}
		case typeSymlink:
			// Unsure what's allowed in this field.
			if !path.IsAbs(e.Linkname) {
				e.Linkname = path.Join(path.Dir(e.Name), e.Linkname)
			}
			fallthrough
		case typeHardlink:
			e.Linkname = normPath(e.Linkname)
		}
		if err := s.add(e, links); err != nil {
			return err
		}
	}
	// Cleanup any dangling hardlinks.
	for _, rms := range links {
		for _, rm := range rms {
			idx := s.lookup[rm]
			delete(s.lookup, rm)
			p := s.meta[s.lookup[path.Dir(rm)]]
			delete(p.children, idx)
		}
	}
	return nil
}

// Add does what it says on the tin.
//
// In addition, it creates any needed leading directory elements.
// The caller should check for the existence of an "out of order" directory, as this function attempts to follow the POSIX spec on actions when "creating" a file that already exists:
// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap01.html#tagtcjh_14
//
// The "hardlink" map is used for deferring hardlink creation.
func (s *srv) add(ne Entry, hardlink map[string][]string) error {
	const op = `create`
	name := ne.Name
Again:
	if i, ok := s.lookup[name]; ok {
		e := &s.entry[i]
		et, nt := e.Type, ne.Type
		switch {
		case nt == typeChunk:
			// Chunks only exist in the seekable variants.
			ni := len(s.entry)
			s.entry = append(s.entry, ne)
			s.meta = append(s.meta, meta{})
			m := &s.meta[i]
			m.chunk = append(m.chunk, ni)
		case nt != typeReg:
			// If the new type isn't a regular file, fail.
			return &fs.PathError{
				Op:   op,
				Path: name,
				Err:  fmt.Errorf("new type (%s) cannot replace existing type (%s): %w", nt, et, fs.ErrExist),
			}
		case et == typeDir:
			// If the existing type is a directory, fail.
			return &fs.PathError{
				Op:   op,
				Path: name,
				Err:  fmt.Errorf("new file cannot replace directory: %w", fs.ErrExist),
			}
		case et == typeSymlink: // Follow the link target.
			name = e.Linkname
			goto Again
		}
		// Should be OK to replace now.
		// Shadow the previous inode so we don't have to renumber everything.
		s.entry[i] = ne
		return nil
	}

	// Hardlink handling: if the target doesn't exist yet, make a note in passed-in map.
	if ne.Type == typeHardlink {
		tgt := ne.Linkname
		if _, ok := s.lookup[tgt]; !ok {
			hardlink[tgt] = append(hardlink[tgt], name)
		}
	}
	delete(hardlink, name)
	i := len(s.entry)
	s.entry = append(s.entry, ne)
	s.meta = append(s.meta, meta{})
	if ne.Type == typeDir {
		s.meta[i].children = make(map[int]struct{})
	}
	s.lookup[name] = i

	cycle := make(map[int]struct{})
	dir := filepath.Dir(name)
AddEnt:
	switch dir {
	case name:
		// Skip
	case ".":
		// Add was called with a root entry, like "a" -- make sure to link this to the root directory.
		root := &s.meta[s.lookup["."]]
		root.children[i] = struct{}{}
	default:
		parent, err := s.getInode(op, dir)
		if err != nil {
			parent, err = s.walkTo(dir, true)
		}
		if err != nil {
			return err
		}
		if _, ok := cycle[parent.N]; ok {
			return &fs.PathError{
				Op:   op,
				Path: dir,
				Err:  fmt.Errorf("found cycle when resolving member: %w", fs.ErrInvalid),
			}
		}
		cycle[parent.N] = struct{}{}
		switch parent.Type {
		case typeDir:
			// OK
		case typeHardlink:
			// This is annoying -- hard linking to directories is weird
			fallthrough
		case typeSymlink:
			dir = parent.Linkname
			goto AddEnt
		default:
			return &fs.PathError{
				Op:   op,
				Path: parent.Entry.Name,
				Err:  fmt.Errorf("error while connecting child %q: %w", name, fs.ErrExist),
			}
		}
		parent.children[i] = struct{}{}
	}
	return nil
}

// GetInode returns an inode backing "name".
//
// The "op" parameter is used in error reporting.
func (s *srv) getInode(op, name string) (inode, error) {
	if !fs.ValidPath(name) {
		return inode{}, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrInvalid,
		}
	}
	if i, ok := s.lookup[name]; ok {
		return s.inodeByIdx(i), nil
	}
	i, err := s.walkTo(name, false)
	if err != nil {
		return inode{}, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}
	return i, nil
}

// InodeByIdx constructs an inode without checking the provided index.
func (s *srv) inodeByIdx(i int) inode {
	return inode{
		Entry: &s.entry[i],
		meta:  &s.meta[i],
		N:     i,
	}
}

// WalkTo does a walk from the root as far along the provided path as possible, resolving symlinks as necessary.
// If any segments are missing (including the final segments), they are created as directories if the "create" bool is passed.
func (s *srv) walkTo(p string, create bool) (inode, error) {
	w := strings.Split(p, "/")
	var cur inode
	var err error
	var b strings.Builder

	cur, err = s.getInode(`walk`, ".")
	if err != nil {
		return cur, err
	}
	i := 0
	for lim := len(w); i < lim; i++ {
		n := w[i]
		if i != 0 {
			b.WriteByte('/')
		}
		b.WriteString(n)
		var child inode
		var found bool
		for ci := range cur.children {
			child = s.inodeByIdx(ci)
			cn := path.Base(child.Entry.Name)
			if cn != n {
				continue
			}
			cycle := make(map[int]struct{})
		Resolve:
			for {
				if _, ok := cycle[ci]; ok {
					return inode{}, &fs.PathError{
						Op:   `walk`,
						Path: b.String(),
						Err:  fmt.Errorf("found cycle when resolving member: %w", fs.ErrInvalid),
					}
				}
				cycle[ci] = struct{}{}
				switch child.Type {
				case typeDir:
					break Resolve
				case typeSymlink:
					tgt := child.Linkname
					var ok bool
					ci, ok = s.lookup[tgt]
					switch {
					case ok && create, ok && !create:
						child = s.inodeByIdx(ci)
						break Resolve
					case !ok && create:
						s.add(newEntryDir(tgt), nil)
						ci = s.lookup[tgt]
						child = s.inodeByIdx(ci)
					case !ok && !create:
						return inode{}, fmt.Errorf("tarfs: walk to %q, but missing segment %q", p, n)
					}
				case typeReg:
					if i == (lim - 1) {
						break Resolve
					}
					return inode{}, &fs.PathError{
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
			s.add(newEntryDir(fp), nil)
			ci := s.lookup[fp]
			child = s.inodeByIdx(ci)
		case !found && !create:
			return inode{}, fmt.Errorf("tarfs: walk to %q, but missing segment %q", p, b.String())
		}
		cur = child
	}
	return cur, nil
}

// Initialized reports whether the numbered inode is initialized or not.
//
// OpenFunc providers should use this to ensure lock invariants.
func (s *srv) initialized(i int) (ok bool) {
	s.mu.RLock()
	ok = s.initd.Bit(i) != 0
	s.mu.RUnlock()
	return ok
}

// Realize calls [srv.open] and updates metadata as needed.
//
// This function is a no-op if a previous call reported a nil error for an equivalent inode.
func (s *srv) realize(i inode) (err error) {
	if s.initialized(i.N) {
		return nil
	}
	var off, sz int64
	switch {
	case i.Type == typeReg && i.Size() != 0:
		// Nonzero regular file
		off, sz, err = s.open(i)
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Check if another goroutine has updated the meta struct and the
	// initialized bitset.
	if s.initd.Bit(i.N) != 0 {
		return nil
	}
	i.meta.off = off
	i.meta.sz = sz
	s.initd.SetBit(&s.initd, i.N, 1)
	return nil
}

// Open implements [fs.FS].
func (s *srv) Open(name string) (fs.File, error) {
	const op = `open`
	i, err := s.getInode(op, name)
	if err != nil {
		return nil, err
	}
	if err := s.realize(i); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}

	r := file{inode: i}
	switch i.Type {
	case typeReg:
		r.SectionReader = io.NewSectionReader(s.raw, i.off, i.sz)
	case typeHardlink:
		i, err = s.getInode(op, name)
		if err != nil {
			return nil, err
		}
		r.inode = i
		r.SectionReader = io.NewSectionReader(s.raw, i.off, i.sz)
	case typeDir:
		r.dirent = make([]fs.DirEntry, len(r.children))
		n := 0
		for i := range r.children {
			e := &s.entry[i]
			r.dirent[n] = dirent{e}
			n++
		}
		sort.Slice(r.dirent, sortDirent(r.dirent))
	case typeSymlink:
		return s.Open(i.Linkname)
	default:
		// Pretend all other kinds of files don't exist.
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  fs.ErrExist,
		}
	}

	return &r, nil
}

// Glob implements [fs.GlobFS].
//
// See [path.Match] for the pattern syntax.
func (s *srv) Glob(pat string) ([]string, error) {
	// GlobFS is implemented because it can avoid allocating for the walk.
	//
	// Path.Match is documented as only returning an error when the pattern is
	// invalid, so check it here and we can avoid the check in the loop.
	if _, err := path.Match(pat, ""); err != nil {
		return nil, err
	}
	var ret []string
	for n := range s.lookup {
		if ok, _ := path.Match(pat, n); ok {
			ret = append(ret, n)
		}
	}
	sort.Strings(ret)
	return ret, nil
}

// ReadFile implements [fs.ReadFileFS].
func (s *srv) ReadFile(name string) ([]byte, error) {
	// ReadFileFS is implemented because it can avoid allocating an intermediate
	// "file" struct and can immediately allocate a byte slice of the correct
	// size.
	const op = `readfile`
	i, err := s.getInode(op, name)
	if err != nil {
		return nil, err
	}
	if i.Type == typeSymlink {
		return s.ReadFile(i.Linkname)
	}
	if err := s.realize(i); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}
	ret := make([]byte, i.sz)
	if _, err := io.ReadFull(io.NewSectionReader(s.raw, i.off, i.sz), ret); err != nil {
		return nil, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  err,
		}
	}
	return ret, nil
}

// Stat implements [fs.StatFS].
func (s *srv) Stat(name string) (fs.FileInfo, error) {
	// StatFS is implemented because it can avoid allocating an intermediate
	// "file" struct.
	const op = `stat`
	i, err := s.getInode(op, name)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ReadDir implements [fs.ReadDirFS].
func (s *srv) ReadDir(name string) ([]fs.DirEntry, error) {
	// ReadDirFS is implemented because it can avoid allocating some
	// intermediate structs.
	const op = `readdir`
	i, err := s.getInode(op, name)
	if err != nil {
		return nil, err
	}
	ret := make([]fs.DirEntry, 0, len(i.children))
	for i := range i.children {
		ret = append(ret, dirent{&s.entry[i]})
	}
	sort.Slice(ret, sortDirent(ret))
	return ret, nil
}
