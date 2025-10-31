// Package ruby contains components for interrogating ruby packages in
// container layers.
package ruby

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rpm"
)

var (
	gemspecPath = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

	// Example gemspec:
	//
	// Gem::Specification.new do |s|
	//   s.name        = 'example'
	//   s.version     = '0.1.0'
	//   s.licenses    = ['MIT']
	//   s.summary     = "This is an example!"
	//   s.description = "Much longer explanation of the example!"
	//   s.authors     = ["Ruby Coder"]
	//   s.email       = 'rubycoder@example.com'
	//   s.files       = ["lib/example.rb"]
	//   s.homepage    = 'https://rubygems.org/gems/example'
	//   s.metadata    = { "source_code_uri" => "https://github.com/example/example" }
	// end
	nameLine    = regexp.MustCompile(`^\S+\.\s*name\s*=\s*(?P<name>\S+)$`)
	versionLine = regexp.MustCompile(`^\S+\.\s*version\s*=\s*(?P<version>\S+)$`)
)

const (
	nameIdx    = 1
	versionIdx = 1

	repository = "rubygems"
)

var (
	_ indexer.VersionedScanner   = (*Scanner)(nil)
	_ indexer.PackageScanner     = (*Scanner)(nil)
	_ indexer.DefaultRepoScanner = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: repository,
		URI:  "https://rubygems.org/gems/",
	}
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for files that seem like gems, and looks at the
// metadata recorded there. This type attempts to follow the specs documented
// here: https://guides.rubygems.org/specification-reference/.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "ruby" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "3" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find gems and record the package information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("ruby: unable to open layer: %w", err)
	}

	gs, err := gems(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("ruby: failed to find packages: %w", err)
	}

	var ret []*claircore.Package
	set, err := rpm.NewPathSet(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("ruby: unable to check RPM db: %w", err)
	}
	for _, g := range gs {
		if set.Contains(g) {
			slog.DebugContext(ctx, "file path determined to be of RPM origin", "path", g)
			continue
		}
		f, err := sys.Open(g)
		if err != nil {
			return nil, fmt.Errorf("ruby: unable to open file: %w", err)
		}

		var name, version string

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if matches := nameLine.FindStringSubmatch(line); matches != nil {
				name = trim(matches[nameIdx])
			}
			if matches := versionLine.FindStringSubmatch(line); matches != nil {
				version = trim(matches[versionIdx])
			}
		}
		if err := scanner.Err(); err != nil {
			slog.WarnContext(ctx, "unable to read metadata, skipping",
				"reason", err,
				"path", g)
			continue
		}

		if name == "" || version == "" {
			slog.WarnContext(ctx, "couldn't parse name or version, skipping", "path", g)
			continue
		}

		ret = append(ret, &claircore.Package{
			Name:           name,
			Version:        version,
			Kind:           claircore.BINARY,
			PackageDB:      "ruby:" + g,
			Filepath:       g,
			RepositoryHint: repository,
		})
	}

	return ret, nil
}

// DefaultRepository implements [indexer.DefaultRepoScanner].
func (Scanner) DefaultRepository(ctx context.Context) *claircore.Repository {
	return &Repository
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, `.freeze`)
	return strings.Trim(s, `'"`)
}

func gems(ctx context.Context, sys fs.FS) (out []string, err error) {
	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		attrs := []slog.Attr{slog.String("file", p)}
		switch {
		case err != nil:
			return err
		case !d.Type().IsRegular():
			// Should we chase symlinks with the correct name?
			return nil
		case strings.HasPrefix(filepath.Base(p), ".wh."):
			return nil
		case gemspecPath.MatchString(p):
			attrs = append(attrs, slog.String("kind", "gem"))
		default:
			return nil
		}
		slog.LogAttrs(ctx, slog.LevelDebug, "found package", attrs...)
		out = append(out, p)
		return nil
	})
}
