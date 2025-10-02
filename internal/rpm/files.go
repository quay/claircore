package rpm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"unique"
	"weak"

	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
)

// PkgCache is a process-wide cache for [PathSet]s.
//
// This allows for all callers to use a single [PathSet] for a given layer.
var pkgCache fileCache

// FileCache implements a cache of [PathSet] values keyed by the layer digest.
type fileCache struct {
	// map[unique.Handle[string]][weak.Pointer[PathSet]]
	m  sync.Map
	sf singleflight.Group
}

func (c *fileCache) cleanupFunc(wp weak.Pointer[PathSet]) func(unique.Handle[string]) {
	return func(key unique.Handle[string]) {
		c.m.CompareAndDelete(key, wp)
	}
}

// GetPathSet returns a [PathSet] for the provided layer, using a cached
// version if possible.
func (c *fileCache) GetPathSet(ctx context.Context, layer *claircore.Layer) (*PathSet, error) {
	// This makes use of [weak.Pointer], which may be odd at first.
	//
	// The weak package has full documentation, but roughly: because a
	// [weak.Pointer] does not keep a value alive for GC purposes, every use
	// that retrieves the original pointer needs to assume that it may have
	// become nil and handle that case before dereferencing it.

	key := unique.Make(layer.Hash.String())
	for {
		v, ok := c.m.Load(key)
		if !ok {
			fn := func() (any, error) {
				if v, ok := c.m.Load(key); ok {
					if s := v.(weak.Pointer[PathSet]).Value(); s != nil {
						return s, nil
					}
					c.m.CompareAndDelete(key, v)
				}

				set := &PathSet{
					paths: make(map[string]struct{}),
				}
				sys, err := layer.FS()
				if err != nil {
					return nil, fmt.Errorf("internal/rpm: unable to open layer: %w", err)
				}
				seq, errFunc := FindDBs(ctx, sys)
				defer func() {
					err = errors.Join(err, errFunc())
				}()

				for found := range seq {
					slog.DebugContext(ctx, "found possible database", "db", found)
					err = func() error {
						db, err := OpenDB(ctx, sys, found)
						if err != nil {
							return err
						}
						defer db.Close()
						log := slog.With("db", db)
						log.DebugContext(ctx, "examining database")
						ct, err := db.populatePathSet(ctx, set)
						if err == nil {
							log.DebugContext(ctx, "processed rpm db",
								"packages", ct,
								"files", set.len())
						}
						return err
					}()
					if err != nil {
						return nil, err
					}

				}
				wp := weak.Make(set)
				runtime.AddCleanup(set, c.cleanupFunc(wp), key)
				c.m.Store(key, wp)
				return set, nil
			}

			ch := c.sf.DoChan(key.Value(), fn)
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			case res := <-ch:
				if err := res.Err; err != nil {
					return nil, err
				}
				return res.Val.(*PathSet), nil
			}
		}

		if s := v.(weak.Pointer[PathSet]).Value(); s != nil {
			return s, nil
		}
		// Unable to upgrade: it's been garbage collected.
		// Attempt to delete it so the next caller just has the load fail,
		// then treat the key as novel.
		c.m.CompareAndDelete(key, v)
	}
}

// NewPathSet returns a [PathSet] for the provided layer.
func NewPathSet(ctx context.Context, layer *claircore.Layer) (*PathSet, error) {
	return pkgCache.GetPathSet(ctx, layer)
}

// PathSet is used to check if a path is an RPM-owned file.
type PathSet struct {
	// Disallow copy to prevent another reference to the "paths" map's
	// backing memory.
	_noCopy noCopy
	paths   map[string]struct{}
}

// Contains reports true if the given path exists in the set of paths that are
// considered to be RPM files in the layer this [PathSet] was created for.
func (s *PathSet) Contains(p string) bool {
	_, exists := s.paths[p]
	return exists
}

// GoString implements [fmt.GoStringer].
func (s *PathSet) GoString() string {
	var b strings.Builder

	b.WriteByte('[')
	for k := range s.paths {
		if b.Len() > 1 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, `%q`, k)
	}
	b.WriteByte(']')

	return b.String()
}

// Len reports the size of the set.
func (s *PathSet) len() int {
	return len(s.paths)
}

// NoCopy is a zero-sized type to trip the "copylocks" vet check.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
