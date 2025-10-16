package claircore

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/quay/zlog"
)

// FilterFS wraps an fs.FS and hides inaccessible files and directories
// by returning appropriate "not found" errors or filtering them from listings.
type FilterFS struct {
	fsys fs.FS
	ctx  context.Context
}

// NewFilterFS creates a new FilterFS wrapper around the provided filesystem.
func NewFilterFS(ctx context.Context, fsys fs.FS) *FilterFS {
	return &FilterFS{fsys: fsys, ctx: ctx}
}

// Open opens the named file for reading. If the file is inaccessible,
// it returns fs.ErrNotExist to hide its existence.
func (f *FilterFS) Open(name string) (fs.File, error) {
	file, err := f.fsys.Open(name)
	if err != nil {
		// Convert permission errors to not found to hide existence
		if os.IsPermission(err) {
			zlog.Debug(f.ctx).Str("path", name).Err(err).Msg("access error on Open")
			return nil, fs.ErrNotExist
		}
		return nil, err
	}

	return file, nil
}

// ReadDir reads and returns directory entries, filtering out inaccessible items.
func (f *FilterFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(f.fsys, name)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.EINVAL) {
			zlog.Debug(f.ctx).Str("path", name).Err(err).Msg("access error on ReadDir")
			return nil, fs.SkipDir
		}
		return nil, err
	}

	// Filter out entries that are inaccessible
	var filtered []fs.DirEntry
	for _, entry := range entries {
		// Try to stat the entry to check if it's accessible
		path := filepath.Join(name, entry.Name())
		_, err := fs.Stat(f.fsys, path)
		if err == nil {
			// Accessible, include it
			filtered = append(filtered, entry)
		} else if !os.IsPermission(err) && !errors.Is(err, syscall.EINVAL) {
			// Other error types should still be included (they might be handled upstream)
			filtered = append(filtered, entry)
		} else {
			// Permission error - log and skip
			isDir := entry.IsDir()
			zlog.Debug(f.ctx).Str("path", path).Bool("is_dir", isDir).Err(err).Msg("access error on entry in ReadDir")
		}
	}

	return filtered, nil
}

// WalkDir walks the directory tree rooted at dir, skipping inaccessible entries.
func (f *FilterFS) WalkDir(name string, fn fs.WalkDirFunc) error {
	return fs.WalkDir(f.fsys, name, func(path string, d fs.DirEntry, err error) error {
		// Hide inaccessible entries by skipping them silently
		if err != nil {
			if os.IsPermission(err) || errors.Is(err, syscall.EINVAL) {
				zlog.Debug(f.ctx).Str("path", path).Err(err).Msg("access error on WalkDir")
				return fs.SkipDir
			}
			return err
		}

		// Verify we can actually access this entry
		_, err = fs.Stat(f.fsys, path)
		if err != nil {
			if os.IsPermission(err) || errors.Is(err, syscall.EINVAL) {
				isDir := d.IsDir()
				zlog.Debug(f.ctx).Str("path", path).Bool("is_dir", isDir).Err(err).Msg("access error in WalkDir on entry verification")
				if isDir {
					return fs.SkipDir
				}
				// Skip file entries silently
				return nil
			}
			return err
		}

		return fn(path, d, nil)
	})
}
