// Package filterfs provides a wrapper around an [fs.FS] that only presents
// regular files and directories to the user.
//
// This wrapper has some overhead, as it attempts to open files to ensure that
// "invisible" permissions (SELinux, etc.) are also valid.
package filterfs

import (
	"io/fs"
	"path"
	"slices"
)

// FS wraps an [fs.FS] and hides inaccessible files and directories
// by returning appropriate "not found" errors or filtering them from listings.
type FS struct {
	fsys fs.FS
}

// New creates a new FS wrapper around the provided filesystem.
func New(fsys fs.FS) *FS {
	return &FS{fsys: fsys}
}

// Open opens the named file for reading and if file is a directory
// wraps it with a ReadFileDir instance that filters out access errors
func (f *FS) Open(name string) (fs.File, error) {
	file, err := f.fsys.Open(name)
	if err != nil {
		return file, err
	}

	fi, err := file.Stat()
	if err != nil {
		return file, err
	}

	if fi.IsDir() {
		return &DirFile{
			fsys:    f,
			fdir:    file,
			pos:     0,
			name:    name,
			entries: nil,
		}, nil
	}

	return file, nil
}

// ReadDir reads and returns directory entries, filtering out inaccessible items.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if _, err := fs.Stat(f.fsys, name); err != nil {
		return nil, fs.SkipDir
	}

	entries, err := fs.ReadDir(f.fsys, name)
	if err != nil {
		return nil, fs.SkipDir
	}
	entries = slices.DeleteFunc(entries, func(d fs.DirEntry) bool {
		p := path.Join(name, d.Name())
		fi, err := fs.Stat(f.fsys, p)
		if err != nil {
			return true
		}
		if m := fi.Mode(); !m.IsDir() && !m.IsRegular() {
			return true
		}
		t, err := f.fsys.Open(p)
		if err != nil {
			return true
		}
		t.Close()
		return false
	})

	return entries, nil
}
