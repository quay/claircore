// Package bom implements consuming Red Hat's java-flavored BOMs.
package bom

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"path"
	"slices"
	"strings"
	"unique"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var (
	// ErrBadFormat is a sentinel error for Red Hat-flavor requirement checks.
	ErrBadFormat = errors.New("java/bom: bad format")

	// ErrTooLarge is returned when a document exceeds [MaxDocument].
	ErrTooLarge = errors.New("java/bom: document exceeds size limit")

	// ErrNoProduct is returned when a document has no product CPE on an excluded
	// framework component or on the root component. Callers should ignore the
	// document and continue scanning.
	ErrNoProduct = errors.New("java/bom: no product CPE")
)

// FormatFromName reports the encoding named by a CycloneDX filename.
// A trailing ".gz" is ignored.
func FormatFromName(name string) (cyclonedx.BOMFileFormat, error) {
	n := path.Base(name)
	n = strings.TrimSuffix(n, ".gz")
	switch {
	case strings.HasSuffix(n, ".cdx.json"):
		return cyclonedx.BOMFileFormatJSON, nil
	case strings.HasSuffix(n, ".cdx.xml"):
		return cyclonedx.BOMFileFormatXML, nil
	default:
		return 0, fmt.Errorf("java/bom: %q is not a CycloneDX filename", name)
	}
}

func formatError(msg string) error {
	return fmt.Errorf("%w: %s", ErrBadFormat, msg)
}

// MaxDocument is the most a compressed CycloneDX document may expand to.
// Jar members use the same limit.
const MaxDocument = 64 << 20

// ReadMax reads r until EOF or one byte past [MaxDocument].
// More than [MaxDocument] bytes returns [ErrTooLarge].
func ReadMax(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(r, MaxDocument+1)); err != nil {
		return nil, err
	}
	if buf.Len() > MaxDocument {
		return nil, ErrTooLarge
	}
	return buf.Bytes(), nil
}

// LoadCDX loads a Red Hat-Java-flavored CycloneDX SBoM in the encoding named by format.
// A compressed document is decompressed before parsing, and that expansion is limited to [MaxDocument].
func LoadCDX(ctx context.Context, r io.ReaderAt, format cyclonedx.BOMFileFormat) (iter.Seq2[Package, error], error) {
	in, kind, err := zreader.Detect(io.NewSectionReader(r, 0, -1))
	if err != nil {
		return nil, fmt.Errorf("java/bom: loading CycloneDX: %w", err)
	}
	defer in.Close()
	rd := io.Reader(in)
	if kind != zreader.KindNone {
		b, err := ReadMax(in)
		if err != nil {
			return nil, fmt.Errorf("java/bom: loading CycloneDX: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	var doc cyclonedx.BOM
	dec := cyclonedx.NewBOMDecoder(rd, format)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("java/bom: loading CycloneDX: %w", err)
	}
	if doc.Metadata == nil || doc.Metadata.Component == nil {
		return nil, formatError("no root component")
	}
	root := doc.Metadata.Component
	if doc.Components == nil || len(*doc.Components) == 0 {
		return nil, formatError("no components")
	}
	if doc.Dependencies == nil || len(*doc.Dependencies) == 0 {
		return nil, formatError("no dependencies")
	}
	cmps := *doc.Components
	deps := *doc.Dependencies
	depidx := slices.IndexFunc(deps, func(d cyclonedx.Dependency) bool {
		return d.Ref == root.BOMRef
	})
	if depidx == -1 {
		return nil, fmt.Errorf("java/bom: missing dependencies of root component %q", root.BOMRef)
	}

	// Product frameworks (scope excluded, with a CPE) attribute Maven purls
	// through their provides lists. A document with none of those keeps the
	// single root CPE on each direct dependency.
	frameworks := make(map[string][]cpe.WFN)
	for i := range cmps {
		cm := &cmps[i]
		if !excludedFramework(cm) {
			continue
		}
		wfns, err := productWFNs(cm)
		if err != nil {
			return nil, fmt.Errorf("java/bom: framework %q: %w", cm.BOMRef, err)
		}
		if len(wfns) == 0 {
			continue
		}
		frameworks[cm.BOMRef] = wfns
	}
	var rootWFNs []cpe.WFN
	attr := map[string][]cpe.WFN{}
	if len(frameworks) == 0 {
		if root.CPE == "" {
			return nil, ErrNoProduct
		}
		wfn, err := cpe.Unbind(root.CPE)
		if err != nil {
			return nil, fmt.Errorf("java/bom: root component %q: %w", root.BOMRef, err)
		}
		rootWFNs = []cpe.WFN{wfn}
	} else {
		for i := range deps {
			d := &deps[i]
			wfns, ok := frameworks[d.Ref]
			if !ok || d.Provides == nil {
				continue
			}
			for _, ref := range *d.Provides {
				attr[ref] = appendWFNs(attr[ref], wfns)
			}
		}
	}

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
		emit := func(cm *cyclonedx.Component, cpes []cpe.WFN) bool {
			if cm == nil {
				return yield(Package{}, errors.New("java/bom: missing component"))
			}
			if !strings.HasPrefix(cm.PackageURL, `pkg:maven/`) {
				skip.Add(cm.PackageURL)
				return true
			}
			purl, err := packageurl.FromString(cm.PackageURL)
			if err != nil {
				return yield(Package{}, fmt.Errorf("java/bom: component %q: %w", cm.BOMRef, err))
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
						return yield(Package{}, fmt.Errorf("java/bom: component %q: %w", cm.BOMRef, err))
					}
					hashes[k] = v
				}
			}
			var loc string
			if ev := cm.Evidence; ev != nil {
				if ocs := ev.Occurrences; ocs != nil {
					for _, oc := range *ocs {
						if oc.Location != "" {
							loc = oc.Location
							break
						}
					}
				}
			}
			ok := yield(Package{
				CPEs:     cpes,
				PURL:     purl,
				Hashes:   hashes,
				Location: loc,
			}, nil)
			if !ok {
				return false
			}
			if err := ctx.Err(); err != nil {
				yield(Package{}, context.Cause(ctx))
				return false
			}
			return true
		}

		if len(frameworks) == 0 {
			dep := &deps[depidx]
			if dep.Dependencies == nil {
				return
			}
			for _, ref := range *dep.Dependencies {
				if !strings.HasPrefix(ref, `pkg:maven/`) {
					skip.Add(ref)
					continue
				}
				if !emit(c[ref], rootWFNs) {
					return
				}
			}
			return
		}
		for i := range cmps {
			cm := &cmps[i]
			if cm.BOMRef == root.BOMRef || excludedFramework(cm) {
				continue
			}
			if !emit(cm, attr[cm.BOMRef]) {
				return
			}
		}
	}

	return seq, nil
}

func excludedFramework(cm *cyclonedx.Component) bool {
	return cm.Type == cyclonedx.ComponentTypeFramework && cm.Scope == cyclonedx.ScopeExcluded
}

// productWFNs returns the product CPEs on a framework component.
// component.cpe is first. Additional CPEs come from evidence.identity.
func productWFNs(cm *cyclonedx.Component) ([]cpe.WFN, error) {
	var out []cpe.WFN
	add := func(s string) error {
		if s == "" {
			return nil
		}
		w, err := cpe.Unbind(s)
		if err != nil {
			return err
		}
		out = appendWFNs(out, []cpe.WFN{w})
		return nil
	}
	if err := add(cm.CPE); err != nil {
		return nil, err
	}
	if cm.Evidence == nil || cm.Evidence.Identity == nil {
		return out, nil
	}
	id := cm.Evidence.Identity
	var ids []cyclonedx.EvidenceIdentity
	if id.Identities != nil {
		ids = append(ids, (*id.Identities)...)
	}
	if id.Identity != nil {
		ids = append(ids, *id.Identity)
	}
	for _, ident := range ids {
		if ident.Field != cyclonedx.EvidenceIdentityFieldTypeCPE {
			continue
		}
		if err := add(ident.ConcludedValue); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func appendWFNs(dst, src []cpe.WFN) []cpe.WFN {
	seen := make(map[string]struct{}, len(dst)+len(src))
	for _, w := range dst {
		seen[w.String()] = struct{}{}
	}
	for _, w := range src {
		s := w.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		dst = append(dst, w)
	}
	return dst
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
