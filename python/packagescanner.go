// Package python contains components for interrogating python packages in
// container layers.
package python

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/textproto"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/pep440"
	"github.com/quay/claircore/pkg/tarfs"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "python" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.1.0" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "python/Scanner.Scan",
		"version", ps.Version(),
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
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("python: unable to open tar: %w", err)
	}

	ms, err := findDeliciousEgg(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("python: failed to find delicious egg: %w", err)
	}
	var ret []*claircore.Package
	for _, n := range ms {
		b, err := fs.ReadFile(sys, n)
		if err != nil {
			return nil, fmt.Errorf("python: unable to read file: %w", err)
		}
		// The two files we read are in RFC8288 (email message) format, and the
		// keys we care about are shared.
		rd := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
		hdr, err := rd.ReadMIMEHeader()
		if err != nil && hdr == nil {
			zlog.Warn(ctx).
				Err(err).
				Str("path", n).
				Msg("unable to read metadata, skipping")
			continue
		}
		v, err := pep440.Parse(hdr.Get("Version"))
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Str("path", n).
				Msg("couldn't parse the version, skipping")
			continue
		}
		ret = append(ret, &claircore.Package{
			Name:              strings.ToLower(hdr.Get("Name")),
			Version:           v.String(),
			PackageDB:         "python:" + filepath.Join(n, "..", ".."),
			Kind:              claircore.BINARY,
			NormalizedVersion: v.Version(),
			// TODO Is there some way to pick up on where a wheel or egg was
			// found?
			RepositoryHint: "https://pypi.org/simple",
		})
	}
	return ret, nil
}

// FindDeliciousEgg finds eggs and wheels.
func findDeliciousEgg(ctx context.Context, sys fs.FS) (out []string, err error) {
	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case !d.Type().IsRegular():
			// Should we chase symlinks with the correct name?
			return nil
		case strings.HasSuffix(p, `.egg-info/PKG-INFO`):
			zlog.Debug(ctx).Str("file", p).Msg("found egg")
		case strings.HasSuffix(p, `.dist-info/METADATA`):
			zlog.Debug(ctx).Str("file", p).Msg("found wheel")
		default:
			return nil
		}
		out = append(out, p)
		return nil
	})
}
