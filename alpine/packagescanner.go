package alpine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"runtime/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	pkgName    = `apk`
	pkgVersion = `v0.0.1`
	pkgKind    = `package`
)

var (
	_ scanner.VersionedScanner = (*Scanner)(nil)
	_ scanner.PackageScanner   = (*Scanner)(nil)
)

// Scanner scans for packages in an apk database.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return pkgName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

// Scan proxies the call to ScanContext.
func (ps *Scanner) Scan(layer *claircore.Layer) ([]*claircore.Package, error) {
	ctx := context.TODO()
	ctx = log.Logger.WithContext(ctx)
	return ps.ScanContext(ctx, layer)
}

const installedFile = "lib/apk/db/installed"

// ScanContext examines a layer for an apk installation database, and extracts
// the packages listed there.
//
// A return of (nil, nil) is expected if there's no apk database.
func (*Scanner) ScanContext(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer:sha256", layer.Hash)
	log := zerolog.Ctx(ctx).With().
		Str("component", "package_scanner").
		Str("name", pkgName).
		Str("version", pkgVersion).
		Str("kind", pkgKind).
		Str("layer", layer.Hash).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	fs, err := layer.Files([]string{installedFile})
	if err != nil {
		return nil, err
	}
	b, ok := fs[installedFile]
	if !ok || len(b) == 0 {
		return nil, nil
	}
	log.Debug().Msg("found database")

	pkgs := []*claircore.Package{}
	srcs := make(map[string]*claircore.Package)
	// It'd be great if we could just use the textproto package here, but we
	// can't because the database "keys" are case sensitive, unlike MIME
	// headers. So, roll our own entry and header splitting.
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Split(split)
	for s.Scan() {
		p := claircore.Package{
			Kind:      "binary",
			PackageDB: installedFile,
		}
		r := bytes.NewBuffer(s.Bytes())
		for line, err := r.ReadBytes('\n'); err == nil; line, err = r.ReadBytes('\n') {
			l := string(bytes.TrimSpace(line[2:]))
			switch line[0] {
			case 'P':
				p.Name = l
			case 'V':
				p.Version = l
			case 'c':
				p.RepositoryHint = l
			case 'o':
				if src, ok := srcs[l]; ok {
					p.Source = src
				} else {
					p.Source = &claircore.Package{
						Name: l,
						Kind: "source",
					}
					if p.Version != "" {
						p.Source.Version = p.Version
					}
					srcs[l] = p.Source
				}
			}
		}
		pkgs = append(pkgs, &p)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	log.Debug().Int("count", len(pkgs)).Msg("found packages")

	return pkgs, nil
}

var delim = []byte("\n\n")

func split(data []byte, atEOF bool) (int, []byte, error) {
	i := bytes.Index(data, delim)
	switch {
	case len(data) == 0 && atEOF:
		return 0, nil, io.EOF
	case len(data) != 0 && atEOF:
		return len(data), data, io.EOF
	case i == -1 && atEOF:
		return 0, nil, errors.New("invalid format")
	case i == -1 && !atEOF:
		return 0, nil, nil
	default:
	}
	tok := data[:i]
	return len(tok) + len(delim), tok, nil
}
