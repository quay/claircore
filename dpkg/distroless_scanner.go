package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"path/filepath"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

const (
	distrolessName    = "dpkg-distroless"
	distrolessKind    = "package"
	distrolessVersion = "1"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// DistrolessScanner implements the scanner.PackageScanner interface.
//
// This looks for directories that look like dpkg databases and examines the
// files it finds there.
//
// The zero value is ready to use.
type DistrolessScanner struct{}

// Name implements scanner.VersionedScanner.
func (ps *DistrolessScanner) Name() string { return distrolessName }

// Version implements scanner.VersionedScanner.
func (ps *DistrolessScanner) Version() string { return distrolessVersion }

// Kind implements scanner.VersionedScanner.
func (ps *DistrolessScanner) Kind() string { return distrolessKind }

// Scan attempts to find a dpkg database files in the layer and read all
// of the installed packages it can find. These files are found in the
// dpkg/status.d directory.
//
// It's expected to return (nil, nil) if there's no dpkg databases in the layer.
//
// It does not respect any dpkg configuration files.
func (ps *DistrolessScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "dpkg/DistrolessScanner.Scan",
		"version", ps.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	rd, err := layer.Reader()
	if err != nil {
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}

	var pkgs []*claircore.Package
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "status.d" && d.IsDir() {
			zlog.Debug(ctx).Str("path", p).Msg("found potential distroless dpkg db directory")
			dbFiles, err := sys.ReadDir(p)
			if err != nil {
				return fmt.Errorf("error reading DB directory: %w", err)
			}
			for _, f := range dbFiles {
				pkgCt := 0
				fn := filepath.Join(p, f.Name())
				ctx = zlog.ContextWithValues(ctx, "database-file", fn)
				zlog.Debug(ctx).Msg("examining package database")
				db, err := sys.Open(fn)
				if err != nil {
					return fmt.Errorf("reading database files from layer failed: %w", err)
				}

				// The database is actually an RFC822-like message with "\n\n"
				// separators, so don't be alarmed by the usage of the "net/textproto"
				// package here.
				tp := textproto.NewReader(bufio.NewReader(db))
			Restart:
				hdr, err := tp.ReadMIMEHeader()
				for ; (err == nil || errors.Is(err, io.EOF)) && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
					// NB The "Status" header is not considered here. It seems
					// to not be populated in the "distroless" scheme.
					name := hdr.Get("Package")
					v := hdr.Get("Version")
					p := &claircore.Package{
						Name:      name,
						Version:   v,
						Kind:      claircore.BINARY,
						Arch:      hdr.Get("Architecture"),
						PackageDB: fn,
					}
					if src := hdr.Get("Source"); src != "" {
						p.Source = &claircore.Package{
							Name: src,
							Kind: claircore.SOURCE,
							// Right now, this is an assumption that discovered source
							// packages relate to their binary versions. We see this in
							// Debian.
							Version:   v,
							PackageDB: fn,
						}
					}
					pkgCt++
					pkgs = append(pkgs, p)
				}
				switch {
				case errors.Is(err, io.EOF):
				default:
					if _, ok := err.(textproto.ProtocolError); ok {
						zlog.Warn(ctx).Err(err).Msg("unable to read DB entry")
						goto Restart
					}
					zlog.Warn(ctx).Err(err).Msg("error reading DB file")
				}
				zlog.Debug(ctx).
					Int("count", pkgCt).
					Msg("found packages")
			}
		}
		return nil
	}

	if err := fs.WalkDir(sys, ".", walk); err != nil {
		return nil, err
	}
	return pkgs, nil
}
