// Package java contains components for interrogating java maven packages in
// container layers.
package java

import (
	"archive/tar"
	"context"
	"io"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/baggageutil"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: "maven",
		URI:  "https://repo1.maven.apache.org/maven2",
	}
)

type RepoScanner struct{}

// Name implements scanner.VersionedScanner.
func (*RepoScanner) Name() string { return "maven" }

// Version implements scanner.VersionedScanner.
func (*RepoScanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*RepoScanner) Kind() string { return "repository" }

// Scan attempts to find jar, war or ear and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (rs *RepoScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "RepoScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = baggageutil.ContextWithValues(ctx,
		"component", "java/RepoScanner.Scan",
		"version", rs.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	tr := tar.NewReader(r)
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		if !isArchive(ctx, h) {
			continue
		}
		// Just claim these came from java.
		return []*claircore.Repository{&Repository}, nil
	}
	if err != io.EOF {
		return nil, err
	}
	return nil, nil
}
