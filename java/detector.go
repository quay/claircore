package java

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/java/bom"
	"github.com/quay/claircore/java/jar"
	"github.com/quay/claircore/rpm"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var _ indexer.RepositoryScanner = (*Detector)(nil)

// Detector records one repository per Red Hat product CPE discovered in a
// Java SBOM. The package scanner cannot return those repositories itself:
// [DefaultRepository] is a single Maven Central repository for the layer.
type Detector struct{}

// Name implements [indexer.VersionedScanner].
func (*Detector) Name() string { return "java" }

// Version implements [indexer.VersionedScanner].
func (*Detector) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (*Detector) Kind() string { return "repository" }

// Scan implements [indexer.RepositoryScanner].
func (*Detector) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf("java: unable to open layer: %w", err)
	}
	set, err := rpm.NewPathSet(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("java: unable to check RPM db: %w", err)
	}
	seen := make(map[string]*claircore.Repository)
	add := func(w cpe.WFN) {
		s := w.String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = &claircore.Repository{
			Name: s,
			Key:  RedHatCPERepositoryKey,
			CPE:  w,
		}
	}

	seq, walkErr := walkInteresting(ctx, sys)
	for k, p := range seq {
		if set.Contains(p) {
			continue
		}
		f, err := sys.Open(p)
		if err != nil {
			return nil, err
		}
		buf, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		switch k {
		case fileSBoM:
			pkgs, err := bom.LoadCDX(ctx, bytes.NewReader(buf))
			if err != nil {
				return nil, err
			}
			for bp, err := range pkgs {
				if err != nil {
					return nil, err
				}
				for _, w := range bp.CPEs {
					add(w)
				}
			}
		case fileJAR:
			z, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
			if err != nil {
				slog.DebugContext(ctx, "not a jar while detecting repositories", "path", p, "reason", err)
				continue
			}
			wfns, err := jar.ProductCPEs(ctx, z)
			if err != nil {
				return nil, err
			}
			for _, w := range wfns {
				add(w)
			}
		default:
			panic("unreachable")
		}
	}
	if err := walkErr(); err != nil {
		return nil, fmt.Errorf("java: walking fs: %w", err)
	}
	out := make([]*claircore.Repository, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	return out, nil
}
