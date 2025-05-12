package rpmtest

import (
	stdcmp "cmp"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unique"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/test/redhat/catalog"
)

type (
	// ManifestRPM is a single RPM as described in the Red Hat Catalog rpm manifest.
	ManifestRPM = catalog.RpmsItems
	// Manifest is a Red Hat Catalog rpm manifest.
	Manifest = catalog.RpmManifest
)

// PackagesFromManifest transforms a sequence of [catalog.RpmsItems] into a
// sequence of [claircore.Package].
func PackagesFromManifest(t *testing.T, items iter.Seq[catalog.RpmsItems]) iter.Seq[claircore.Package] {
	t.Helper()
	return func(yield func(claircore.Package) bool) {
		t.Helper()
		srcs := make([]claircore.Package, 0)
		src := make(map[unique.Handle[rpmver.Version]]*claircore.Package)
		n := 0

		for it := range items {
			n++
			pv, err := rpmver.Parse(stdcmp.Or(
				it.NVRA,
				fmt.Sprintf("%s-%s:%s-%s.%s",
					it.Name, stdcmp.Or(it.Epoch, "0"), it.Version, it.Release, it.Architecture)))
			if err != nil {
				t.Errorf("#%03d: (%#v) unable to determine version: %v", n, it, err)
				continue
			}

			if it.SrpmName == "" && it.SrpmNEVRA == "" {
				// This is a binary package with no source information. This can be discounted.
				continue
			}

			// Newer images produced from Konflux shove all the source information
			// into the SourceName and omit the SourceNEVRA. Try both.
			//
			// This sometimes has ".rpm" on it?
			sv, err := rpmver.Parse(strings.TrimSuffix(stdcmp.Or(it.SrpmNEVRA, it.SrpmName), ".rpm"))
			if err != nil {
				t.Errorf("#%03d: (%#v) unable to determine source version: %v", n, it, err)
				continue
			}

			p := claircore.Package{
				Name:           it.Name,
				Version:        pv.EVR(),
				Kind:           "binary",
				Arch:           it.Architecture,
				RepositoryHint: url.Values{"key": {it.GPG}}.Encode(),
				Module:         it.Module,
			}
			srckey := unique.Make(sv)
			if s, ok := src[srckey]; ok {
				p.Source = s
			} else {
				idx := len(srcs)
				srcs = append(srcs, claircore.Package{
					Kind:    "source",
					Name:    *sv.Name,
					Version: sv.EVR(),
					Module:  it.Module,
				})
				src[srckey] = &srcs[idx]
				p.Source = &srcs[idx]
			}

			if !yield(p) {
				return
			}
		}
	}
}

// PackagesFromRPMManifest loads the rpm manifest in "r" and returns the
// contents as transformed into [claircore.Package]s.
func PackagesFromRPMManifest(t *testing.T, r io.Reader) []*claircore.Package {
	t.Helper()
	var m catalog.RpmManifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(m.RPMs, func(a, b ManifestRPM) int {
		return strings.Compare(a.Name, b.Name)
	})

	items := slices.Values(m.RPMs)
	pkgs := PackagesFromManifest(t, items)
	ptrs := wart.AsPointer(pkgs)
	return slices.Collect(ptrs)
}
