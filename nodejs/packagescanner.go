// Package nodejs contains components for interrogating nodejs packages in
// container layers.
package nodejs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const repository = "npm"

var (
	_ indexer.VersionedScanner   = (*Scanner)(nil)
	_ indexer.PackageScanner     = (*Scanner)(nil)
	_ indexer.DefaultRepoScanner = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: repository,
		URI:  "https://www.npmjs.com/",
	}
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files that seem like package.json and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "nodejs" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// packageJSON represents the fields of a package.json file
// useful for package scanning.
//
// See https://docs.npmjs.com/files/package.json/ for more details
// about the format of package.json files.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Scan attempts to find package.json files and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (s *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "nodejs/Scanner.Scan",
		"version", s.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("nodejs: unable to open layer: %w", err)
	}

	pkgs, err := packages(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("nodejs: failed to find packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	ret := make([]*claircore.Package, 0, len(pkgs))
	for _, p := range pkgs {
		f, err := sys.Open(p)
		if err != nil {
			return nil, fmt.Errorf("nodejs: unable to open file: %w", err)
		}

		var pkgJSON packageJSON
		err = json.NewDecoder(bufio.NewReader(f)).Decode(&pkgJSON)
		if err != nil {
			return nil, fmt.Errorf("nodejs: unable to decode package.json file: %w", err)
		}

		ret = append(ret, &claircore.Package{
			Name:           pkgJSON.Name,
			Version:        pkgJSON.Version,
			Kind:           claircore.BINARY,
			PackageDB:      "nodejs:" + p,
			RepositoryHint: repository,
		})
	}

	return ret, nil
}

func packages(ctx context.Context, sys fs.FS) (out []string, err error) {
	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		ev := zlog.Debug(ctx).
			Str("file", p)
		var success bool
		defer func() {
			if !success {
				ev.Discard().Send()
			}
		}()
		switch {
		case err != nil:
			return err
		case !d.Type().IsRegular():
			// Should we chase symlinks with the correct name?
			return nil
		case strings.HasPrefix(filepath.Base(p), ".wh."):
			return nil
		case !strings.Contains(p, "node_modules/"):
			// Only bother with package.json files within node_modules/ directories.
			// See https://docs.npmjs.com/cli/v7/configuring-npm/folders#node-modules
			// for more information.
			return nil
		case strings.HasSuffix(p, "/package.json"):
			ev = ev.Str("kind", "package.json")
		default:
			return nil
		}
		ev.Msg("found package")
		success = true
		out = append(out, p)
		return nil
	})
}

// DefaultRepository implements [indexer.DefaultRepoScanner].
func (*Scanner) DefaultRepository(_ context.Context) *claircore.Repository {
	return &Repository
}
