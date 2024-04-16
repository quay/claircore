package rpm

import (
	"context"
	"fmt"
	"io/fs"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	scannerName    = "rpm"
	scannerVersion = "1"
	scannerKind    = "file"
)

var (
	_ indexer.FileScanner      = (*FileScanner)(nil)
	_ indexer.VersionedScanner = (*FileScanner)(nil)
)

// FileScanner implements [indexer.FileScanner], it examines RPM
// databases and reports installed files.
type FileScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*FileScanner) Name() string { return scannerName }

// Version implements [indexer.VersionedScanner].
func (*FileScanner) Version() string { return scannerVersion }

// Kind implements [indexer.VersionedScanner]
func (*FileScanner) Kind() string { return scannerKind }

// Scan reports any found Files that were installed via RPMs in the
// layer.
//
// It's an expected outcome to return (nil, nil) when no RPM packages are found in the Layer.
func (s *FileScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]claircore.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "FileScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "rpm/FileScanner.Scan",
		"version", s.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("rpm: unable to open layer: %w", err)
	}

	found := make([]foundDB, 0)
	if err := fs.WalkDir(sys, ".", findDBs(ctx, &found, sys)); err != nil {
		return nil, fmt.Errorf("rpm: error walking fs: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}

	done := map[string]struct{}{}
	files := []claircore.File{}

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
		files = append(files, fs...)
	}

	return files, nil
}
