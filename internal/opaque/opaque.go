// Package opaque ...
package opaque

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/quay/claircore/libindex/driver"
)

// Indexer implements the OpaqueIndexer.
type Indexer struct{}

// Name implements driver.Scanner.
func (*Indexer) Name() string {
	return "claircore/opaque"
}

// Version implements driver.Scanner.
func (*Indexer) Version() string {
	return "1"
}

// Init implements driver.Scanner.
func (*Indexer) Init(context.Context, driver.ConfigFunc) error {
	return nil
}

// Whiteout is the filename recorded for an "opaque" whiteout.
//
// See https://github.com/opencontainers/image-spec/blob/main/layer.md#opaque-whiteout
const whiteout = `.wh..wh..opq`

// IndexOpaque reports any discovered opaque whiteouts.
func (*Indexer) IndexOpaque(ctx context.Context, l fs.FS) ([]driver.LayerChange[driver.Opaque], error) {
	var ret []driver.LayerChange[driver.Opaque]
	err := fs.WalkDir(l, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case !d.IsDir():
			return nil
		case !errors.Is(ctx.Err(), nil):
			return ctx.Err()
		}
		if _, err := fs.Stat(l, filepath.Join(path, whiteout)); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		ret = append(ret, driver.LayerChange[driver.Opaque]{
			Location: path,
			Op:       driver.OpRemove,
		})
		return fs.SkipDir
	})
	return ret, err
}
