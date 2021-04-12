// Package java contains components for interrogating java maven packages in
// container layers.
package java

import (
	"archive/tar"
	"context"
	"io"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "java/RepoScanner.Scan"),
		label.String("version", rs.Version()),
		label.String("layer", layer.Hash.String()))
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
		n, err := filepath.Rel("/", filepath.Join("/", h.Name))
		if err != nil {
			return nil, err
		}
		switch {
		case h.Typeflag != tar.TypeReg:
			// Should we chase symlinks with the correct name?
			continue
		case strings.HasSuffix(n, `.jar`):
			zlog.Debug(ctx).Str("file", n).Msg("found jar")
		case strings.HasSuffix(n, `.war`):
			zlog.Debug(ctx).Str("file", n).Msg("found war")
		case strings.HasSuffix(h.Name, `.ear`):
			zlog.Debug(ctx).Str("file", h.Name).Msg("found ear")
		default:
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
