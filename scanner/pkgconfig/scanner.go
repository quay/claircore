// Package pkgconfig implements a scanner that finds pkg-config files.
//
// Pkg-config is a widely-used package for finding linker and compiler flags on
// Linux systems.
package pkgconfig

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/baggageutil"
	"github.com/quay/claircore/internal/indexer"
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
	ctx = baggageutil.ContextWithValues(ctx,
		"component", "scanner/pkgconfig/Scanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(r)
	var h *tar.Header
	var buf bytes.Buffer
	var ret []*claircore.Package

	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n, err := filepath.Rel("/", filepath.Join("/", h.Name))
		if err != nil {
			return nil, err
		}
		if filepath.Ext(n) != ".pc" {
			continue
		}
		zlog.Debug(ctx).
			Str("path", n).
			Msg("found possible pkg-config file")
		if _, err := buf.ReadFrom(tr); err != nil {
			return nil, err
		}
		var pc pc
		switch err := pc.Scan(&buf); err {
		case nil:
		case errInvalid: // skip
			zlog.Info(ctx).
				Str("path", n).
				Msg("invalid pkg-config file")
			continue
		default:
			return nil, err
		}
		ret = append(ret, &claircore.Package{
			Name:           pc.Name,
			Version:        pc.Version,
			PackageDB:      filepath.Dir(n),
			RepositoryHint: pc.URL,
		})
	}

	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}

/*
Below implements a subset of a pkg-config file scanner.

In theory, we could just look for the Name an Version fields, extract the value,
and be on our way. But the C source (https://cgit.freedesktop.org/pkg-config/tree/parse.c)
makes sure to run all values through trim_and_sub, so we should do the same.
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
