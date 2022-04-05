// Package pkgconfig implements a scanner that finds pkg-config files.
//
// Pkg-config is a widely-used package for finding linker and compiler flags on
// Linux systems.
package pkgconfig

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

var _ indexer.PackageScanner = (*Scanner)(nil)

const (
	pkgName    = `pkgconfig`
	pkgVersion = `0.0.1`
	pkgKind    = `package`
)

// Scanner finds pkg-config files in layers.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return pkgName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

// Scan attempts to find and enumerate pkg-config files.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "scanner/pkgconfig/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := layer.Reader()
	if err != nil {
		return nil, fmt.Errorf("pkgconfig: opening layer failed: %w", err)
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("pkgconfig: opening layer failed: %w", err)
	}

	var ret []*claircore.Package
	err = fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case filepath.Ext(d.Name()) != ".pc":
			return nil
		}
		zlog.Debug(ctx).
			Str("path", p).
			Msg("found possible pkg-config file")
		f, err := sys.Open(p)
		if err != nil {
			return err
		}
		var pc pc
		err = pc.Scan(f)
		f.Close()
		switch {
		case errors.Is(nil, err):
		case errors.Is(errInvalid, err): // skip
			zlog.Info(ctx).
				Str("path", p).
				Msg("invalid pkg-config file")
			return nil
		default:
			return err
		}
		ret = append(ret, &claircore.Package{
			Name:           pc.Name,
			Version:        pc.Version,
			PackageDB:      filepath.Dir(p),
			RepositoryHint: pc.URL,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

/*
Below implements a subset of a pkg-config file scanner.

In theory, we could just look for the Name and Version fields, extract the
value, and be on our way. But the C source
(https://cgit.freedesktop.org/pkg-config/tree/parse.c) makes sure to run all
values through trim_and_sub, so we should do the same.
*/

type pc struct {
	Name    string
	Version string
	URL     string
}

func (pc *pc) Done() bool {
	return pc.Name != "" &&
		pc.Version != "" &&
		pc.URL != ""
}

func (pc *pc) Err() bool {
	return pc.Name != "" && pc.Version != ""
}

var errInvalid = errors.New("")

func (pc *pc) Scan(r io.Reader) error {
	vs := make(map[string]string)
	expand := func(k string) string { return vs[k] }
	s := bufio.NewScanner(r)

	for s.Scan() && !pc.Done() {
		b := s.Bytes()
		i := bytes.IndexAny(b, ":=")
		if i == -1 {
			continue
		}
		tag := string(bytes.TrimSpace(b[:i]))
		val := string(bytes.TrimSpace(b[i+1:]))
		switch b[i] {
		case '=': // Variable assignment
			if _, exists := vs[tag]; exists {
				return fmt.Errorf("duplicate variable assignment: %q", tag)
			}
			val = os.Expand(val, expand)
			vs[tag] = val
		case ':': // Key-Value
			switch tag {
			case "Name":
				pc.Name = os.Expand(val, expand)
			case "Version":
				pc.Version = os.Expand(val, expand)
			case "URL":
				pc.URL = os.Expand(val, expand)
			default: // skip
			}
		default:
			panic("unreachable")
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	if !pc.Err() {
		return errInvalid
	}
	return nil
}
