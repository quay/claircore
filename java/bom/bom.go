// Package bom implements consuming Red Hat's java-flavored BOMs.
package bom

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"slices"
	"strings"
	"unique"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore/toolkit/types/cpe"
)

// ErrBadFormat is a sentinel error for Red Hat-flavor requirement checks.
var ErrBadFormat = errors.New("bad format")

func formatError(format string, a ...any) error {
	return &errorFormat{inner: fmt.Errorf(format, a...)}
}

type errorFormat struct {
	inner error
}

func (e *errorFormat) Error() string {
	return fmt.Sprintf("java/bom: bad format: %v", e.inner)
}

func (e *errorFormat) Unwrap() error {
	return e.inner
}

func (e *errorFormat) Is(tgt error) bool {
	return tgt == ErrBadFormat
}

// LoadCDX loads the Red Hat-Java-flavored CycloneDX JSON SBoM.
func LoadCDX(ctx context.Context, r io.ReaderAt) (iter.Seq2[Package, error], error) {
	var doc cyclonedx.BOM
	dec := cyclonedx.NewBOMDecoder(io.NewSectionReader(r, 0, -1), cyclonedx.BOMFileFormatJSON)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("java/bom: loading CycloneDX: %w", err)
	}
	root := doc.Metadata.Component
	if root == nil {
		return nil, formatError("no root component")
	}
	if doc.Components == nil || len(*doc.Components) == 0 {
		return nil, formatError("no components")
	}
	if doc.Dependencies == nil || len(*doc.Dependencies) == 0 {
		return nil, formatError("no dependencies")
	}
	wfn, err := cpe.Unbind(root.CPE)
	if err != nil {
		return nil, fmt.Errorf("java/bom: root component %q: %w", root.BOMRef, err)
	}
	cmps := *doc.Components
	deps := *doc.Dependencies

	seq := func(yield func(Package, error) bool) {
		var skip skipPurls
		defer func() {
			if skip.count == 0 {
				return
			}
			slog.DebugContext(ctx, "skipped some purls", "skipped", &skip)
		}()
		c := make(map[string]*cyclonedx.Component, len(cmps))
		for i := range cmps {
			r := &cmps[i]
			c[r.BOMRef] = r
		}
		depidx := slices.IndexFunc(deps, func(d cyclonedx.Dependency) bool {
			return d.Ref == root.BOMRef
		})
		if depidx == -1 {
			err := fmt.Errorf("java/bom: missing dependencies of root component %q", root.BOMRef)
			yield(Package{}, err)
			return
		}
		dep := &deps[depidx]
	YieldPackages:
		for _, ref := range *dep.Dependencies {
			if strings.HasPrefix(ref, `pkg:generic/`) {
				skip.Add(ref)
				continue
			}
			cm := c[ref]
			purl, err := packageurl.FromString(cm.PackageURL)
			if err != nil {
				err := fmt.Errorf("java/bom: component %q: %w", cm.BOMRef, err)
				if !yield(Package{}, err) {
					return
				}
				continue
			}
			var hashes map[unique.Handle[string]][]byte
			if cm.Hashes != nil {
				hs := *cm.Hashes
				hashes = make(map[unique.Handle[string]][]byte, len(hs))
				for _, h := range hs {
					k, known := hashnames[h.Algorithm]
					if !known {
						continue
					}
					// Assume everything is encoded as hex:
					v, err := hex.DecodeString(h.Value)
					if err != nil {
						err := fmt.Errorf("java/bom: component %q: %w", cm.BOMRef, err)
						if !yield(Package{}, err) {
							return
						}
						continue YieldPackages
					}
					hashes[k] = v
				}
			}
			var loc string
			if ev := cm.Evidence; ev != nil {
				if ocs := ev.Occurrences; ocs != nil {
				Occurrence:
					for _, oc := range *ocs {
						if oc.Location != "" {
							loc = oc.Location
							break Occurrence
						}
					}
				}
			}

			pkg := Package{
				CPE:      &wfn,
				PURL:     purl,
				Hashes:   hashes,
				Location: loc,
			}
			if !yield(pkg, nil) {
				return
			}
			if err := ctx.Err(); err != nil {
				yield(Package{}, context.Cause(ctx))
				return
			}
		}
	}

	return seq, nil
}

var _ slog.LogValuer = (*skipPurls)(nil)

type skipPurls struct {
	examples []string
	count    int
}

func (s *skipPurls) Add(p string) {
	if len(s.examples) < 16 {
		s.examples = append(s.examples, p)
	}
	s.count++
}

// LogValue implements [slog.LogValuer].
func (s *skipPurls) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("count", s.count),
		slog.Any("examples", s.examples),
	)
}
