// Package java contains components for interrogating java packages in
// container layers.
package java

import (
	"archive/tar"
	"context"
	"io"
	"path/filepath"
	"runtime/trace"

	"github.com/aquasecurity/go-dep-parser/pkg/jar"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files that seem like jar, war or ear, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "java" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find jar, war or ear files and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "java/Scanner.Scan"),
		label.String("version", ps.Version()),
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

	var ret []*claircore.Package
	tr := tar.NewReader(r)
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		if !isArchive(ctx, h) {
			continue
		}
		packages, err := getPackagesFromJarFamily(tr, h.Name)
		if err != nil {
			return nil, err
		}
		ret = append(ret, packages...)
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}

func getPackagesFromJarFamily(r io.Reader, name string) ([]*claircore.Package, error) {
	n, err := filepath.Rel("/", filepath.Join("/", name))
	libs, err := jar.Parse(r, jar.WithFilePath(n))
	if err != nil {
		return nil, err
	}
	packages := make([]*claircore.Package, len(libs))
	for i, l := range libs {
		packages[i] = &claircore.Package{
			Name:           l.Name,
			Version:        l.Version,
			PackageDB:      "maven:" + filepath.Join(n, ".."),
			Kind:           claircore.BINARY,
			RepositoryHint: Repository.URI,
		}
	}
	return packages, nil
}
