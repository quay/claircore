package filterfs

import (
	"io/fs"
	"path"
)

// FS wraps an fs.FS and hides inaccessible files and directories
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

	var filtered []fs.DirEntry
	// Filter out entries that are inaccessible
	for _, entry := range entries {
		// Try to stat the entry to check if it's accessible
		path := path.Join(name, entry.Name())
		fi, err := fs.Stat(f.fsys, path)
		if err == nil {
			// Accessible, include it
			if fi.Mode().IsRegular() || fi.Mode().IsDir() {
				if file, err := f.fsys.Open(path); err == nil {
					file.Close()
					filtered = append(filtered, entry)
				}
			}
		}
	}

	return filtered, nil
}
