package rpm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/quay/zlog"
	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
)

// FilesCache is used for concurrent access to the map containing
// [claircore.Layer] -> map[string]struct{}.
type filesCache struct {
	c    map[string]map[string]struct{}
	refs map[string]int
	mu   sync.Mutex
	sf   singleflight.Group
	// wg tracks the gc calls made during get. This is particularly useful
	// during testing, so we can wait on all the gc calls before asserting
	// the cache is indeed empty and all the references were accounted for.
	wg sync.WaitGroup
}

var fc = &filesCache{
	c:    map[string]map[string]struct{}{},
	refs: map[string]int{},
}

// GC decrements the reference counter and deletes the [claircore.Layer]'s
// entry from the cache map and the reference counter once the references
// are 0 (or less).
func (fc *filesCache) gc(key string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.refs[key]--
	if fc.refs[key] <= 0 {
		delete(fc.c, key)
		delete(fc.refs, key)
		fc.sf.Forget(key)
	}
}

// Get increments the reference counter for the key and looks up the key
// in the cache. It will subsequently start a goroutine to track when the
// calling context is done, calling the gc method.
func (fc *filesCache) get(ctx context.Context, key string) (map[string]struct{}, bool) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.refs[key]++
	f, ok := fc.c[key]
	fc.wg.Add(1)
	go func() {
		defer fc.wg.Done()
		<-ctx.Done()
		fc.gc(key)
	}()
	return f, ok
}

// Set sets the files for a particular key and deals with the locking.
func (fc *filesCache) set(key string, files map[string]struct{}) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.c[key] = files
}

var errNoDBFound = errors.New("no RPM DB found")

// GetFiles looks up RPM files that exist in the RPM database using the
// filesFromDB function and memoizes the result to avoid repeated work
// for the same [claircore.Layer].
func (fc *filesCache) getFiles(ctx context.Context, layer *claircore.Layer) (map[string]struct{}, error) {
	key := layer.Hash.String()
	if files, ok := fc.get(ctx, key); ok {
		return files, nil
	}

	files := map[string]struct{}{}
	ch := fc.sf.DoChan(key, func() (interface{}, error) {
		sys, err := layer.FS()
		if err != nil {
			return nil, fmt.Errorf("rpm: unable to open layer: %w", err)
		}

		found := make([]foundDB, 0)
		if err := fs.WalkDir(sys, ".", findDBs(ctx, &found, sys)); err != nil {
			return nil, fmt.Errorf("rpm: error walking fs: %w", err)
		}
		if len(found) == 0 {
			return nil, errNoDBFound
		}

		done := map[string]struct{}{}
		zlog.Debug(ctx).Int("count", len(found)).Msg("found possible databases")
		for _, db := range found {
			ctx := zlog.ContextWithValues(ctx, "db", db.String())
			zlog.Debug(ctx).Msg("examining database")
			if _, ok := done[db.Path]; ok {
				zlog.Debug(ctx).Msg("already seen, skipping")
				continue
			}
			done[db.Path] = struct{}{}
			fs, err := getDBObjects(ctx, sys, db, filesFromDB)
			if err != nil {
				return nil, fmt.Errorf("rpm: error getting native DBs: %w", err)
			}
			for _, f := range fs {
				files[f.Path] = struct{}{}
			}
		}
		fc.set(key, files)
		return files, nil
	})
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case res := <-ch:
		switch {
		case res.Err == nil:
			files = res.Val.(map[string]struct{})
		case errors.Is(res.Err, errNoDBFound):
		default:
			return nil, res.Err
		}
	}

	return files, nil
}

// NewFileChecker creates a new FileChecker using the file cache to memoize lookups
// of the set of paths that are RPM files.
func NewFileChecker(ctx context.Context, layer *claircore.Layer) (*FileChecker, error) {
	fs, err := fc.getFiles(ctx, layer)
	if err != nil {
		return nil, err
	}
	return &FileChecker{
		files: fs,
	}, nil
}

// FileChecker is used to check if a path is an RPM file.
type FileChecker struct {
	files map[string]struct{}
}

// IsRPM returns true if the given path exists in the set of paths that are
// considered to be RPM files in the layer this FileChecker was created for.
func (fc *FileChecker) IsRPM(path string) bool {
	_, exists := fc.files[path]
	return exists
}
