package rpm

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/zlog"
)

// filesCache is used for concurrent access to the map containing layer.Hash -> map RPM files.
// The value is a map to allow for quick member checking.
type filesCache struct {
	c  map[string]map[string]struct{}
	mu *sync.Mutex
}

var fc *filesCache

func init() {
	fc = &filesCache{
		c:  map[string]map[string]struct{}{},
		mu: &sync.Mutex{},
	}
}

// gc deletes the layer's entry from the map if the ctx is done, this ties the lifecycle of
// the cached information to the request lifecycle to avoid excessive memory consumption.
func (fc *filesCache) gc(ctx context.Context, key string) {
	<-ctx.Done()
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.c, key)
}

// getFiles looks up RPM files that exist in the RPM database using the filesFromDB
// function and memorizes the result to avoid repeated work for the same claircore.Layer.
func (fc *filesCache) getFiles(ctx context.Context, layer *claircore.Layer) (map[string]struct{}, error) {
	if fc == nil {
		panic("programmer error: filesCache nil")
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if files, ok := fc.c[layer.Hash.String()]; ok {
		return files, nil
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("rpm: unable to open layer: %w", err)
	}

	files := map[string]struct{}{}
	defer func() {
		// Defer setting the cache so any early-outs don't have to worry.
		fc.c[layer.Hash.String()] = files
	}()
	found := make([]foundDB, 0)
	if err := fs.WalkDir(sys, ".", findDBs(ctx, &found, sys)); err != nil {
		return nil, fmt.Errorf("rpm: error walking fs: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
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
	go func() {
		fc.gc(ctx, layer.Hash.String())
	}()

	return files, nil
}

// FileInstalledByRPM takes a claircore.Layer and filepath string and returns a boolean
// signifying whether that file came from an RPM package.
func FileInstalledByRPM(ctx context.Context, layer *claircore.Layer, filepath string) (bool, error) {
	files, err := fc.getFiles(ctx, layer)
	if err != nil {
		return false, err
	}
	_, exists := files[filepath]
	return exists, nil
}
