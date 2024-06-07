package tarfs

import (
	"archive/tar"
	"io"
	"io/fs"
	"path"
	"strings"
)

var _ fs.File = (*file)(nil)

// File implements fs.File.
type file struct {
	h *tar.Header
	r *tar.Reader
}

func (f *file) Close() error {
	return nil
}

func (f *file) Read(b []byte) (int, error) {
	return f.r.Read(b)
}

func (f *file) Stat() (fs.FileInfo, error) {
	return f.h.FileInfo(), nil
}

var _ fs.ReadDirFile = (*dir)(nil)

// Dir implements fs.ReadDirFile.
type dir struct {
	h   *tar.Header
	es  []fs.DirEntry
	pos int
}

func (*dir) Close() error                 { return nil }
func (*dir) Read(_ []byte) (int, error)   { return 0, io.EOF }
func (d *dir) Stat() (fs.FileInfo, error) { return d.h.FileInfo(), nil }
func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	es := d.es[d.pos:]
	if len(es) == 0 {
		if n == -1 {
			return nil, nil
		}
		return nil, io.EOF
	}
	end := min(len(es), n)
	if n == -1 {
		end = len(es)
	}
	d.pos += end
	return es[:end], nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type dirent struct{ *tar.Header }

var _ fs.DirEntry = dirent{}

func (d dirent) Name() string               { return path.Base(d.Header.Name) }
func (d dirent) IsDir() bool                { return d.Header.FileInfo().IsDir() }
func (d dirent) Type() fs.FileMode          { return d.Header.FileInfo().Mode() & fs.ModeType }
func (d dirent) Info() (fs.FileInfo, error) { return d.FileInfo(), nil }

// SortDirent returns a function suitable to pass to sort.Slice as a "cmp"
// function.
//
// This is needed because the fs interfaces specify that DirEntry slices
// returned by the ReadDir methods are sorted lexically.
func sortDirent(s []fs.DirEntry) func(i, j int) bool {
	return func(i, j int) bool {
		return strings.Compare(s[i].Name(), s[j].Name()) == -1
	}
}
