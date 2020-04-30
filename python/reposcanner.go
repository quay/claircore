// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: "pypi",
		URI:  "https://pypi.org/simple",
	}
)

type RepoScanner struct{}

// Name implements scanner.VersionedScanner.
func (*RepoScanner) Name() string { return "pip" }

// Version implements scanner.VersionedScanner.
func (*RepoScanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*RepoScanner) Kind() string { return "repository" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (rs *RepoScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "RepoScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := zerolog.Ctx(ctx).With().
		Str("component", "python/RepoScanner.Scan").
		Str("version", rs.Version()).
		Str("layer", layer.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("python: cannot seek on returned layer Reader")
	}

	tr := tar.NewReader(rd)
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
		case strings.HasSuffix(n, `.egg-info/PKG-INFO`):
			log.Debug().Str("file", n).Msg("found egg")
		case strings.HasSuffix(n, `.dist-info/METADATA`):
			log.Debug().Str("file", n).Msg("found wheel")
		default:
			continue
		}

		// Just claim these came from pypi.
		return []*claircore.Repository{&Repository}, nil
	}
	if err != io.EOF {
		return nil, err
	}
	return nil, nil
}
