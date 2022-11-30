package rpmtest

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
)

type Manifest struct {
	RPM []ManifestRPM `json:"rpms"`
}
type ManifestRPM struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
	Arch    string `json:"architecture"`
	Source  string `json:"srpm_nevra"`
	GPG     string `json:"gpg"`
}

func PackagesFromRPMManifest(t *testing.T, r io.Reader) []*claircore.Package {
	t.Helper()
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatal(err)
	}
	out := make([]*claircore.Package, 0, len(m.RPM))
	srcs := make([]claircore.Package, 0, len(m.RPM))
	src := make(map[string]*claircore.Package)
	for _, rpm := range m.RPM {
		p := claircore.Package{
			Name:           rpm.Name,
			Version:        rpm.Version + "-" + rpm.Release,
			Kind:           "binary",
			Arch:           rpm.Arch,
			RepositoryHint: "key:" + rpm.GPG,
		}
		if s, ok := src[rpm.Source]; ok {
			p.Source = s
		} else {
			s := strings.TrimSuffix(rpm.Source, ".src")
			pos := len(s)
			for i := 0; i < 2; i++ {
				pos = strings.LastIndexByte(s[:pos], '-')
				if pos == -1 {
					t.Fatalf("malformed NEVRA: %q", rpm.Source)
				}
			}
			idx := len(srcs)
			srcs = append(srcs, claircore.Package{
				Kind:    "source",
				Name:    s[:pos],
				Version: strings.TrimPrefix(s[pos+1:], "0:"),
			})
			src[rpm.Source] = &srcs[idx]
			p.Source = &srcs[idx]
		}
		out = append(out, &p)
	}
	return out
}

var Options = cmp.Options{
	HintCompare,
	EpochCompare,
	IgnorePackageDB,
	IgnoreGPGPubkey,
	SortPackages,
}

// RPM Manifest doesn't have checksum information. It does have keyid information,
// so cook up a comparison function that understands the rpm package's packed format.
var HintCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".RepositoryHint" },
	cmp.Comparer(func(a, b string) bool {
		am, bm := make(map[string]string), make(map[string]string)
		for _, s := range strings.Split(a, "|") {
			if s == "" {
				continue
			}
			k, v, ok := strings.Cut(s, ":")
			if !ok {
				panic("odd format: " + s)
			}
			am[k] = v
		}
		delete(am, "hash")
		for _, s := range strings.Split(b, "|") {
			if s == "" {
				continue
			}
			k, v, ok := strings.Cut(s, ":")
			if !ok {
				panic("odd format: " + s)
			}
			bm[k] = v
		}
		delete(bm, "hash")
		return cmp.Equal(am, bm)
	}),
)

// RPM Manifest doesn't have package epoch information.
// This checks if the VR string is contained in the EVR string.
var EpochCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".Version" },
	cmp.Comparer(func(a, b string) bool {
		evr, vr := a, b
		if len(b) > len(a) {
			evr = b
			vr = a
		}
		return strings.Contains(evr, vr)
	}),
)

// Does what it says on the tin.
var (
	IgnoreGPGPubkey = cmpopts.IgnoreSliceElements(func(p *claircore.Package) bool {
		return p.Name == `gpg-pubkey`
	})
	SortPackages = cmpopts.SortSlices(func(a, b *claircore.Package) bool {
		return a.Name < b.Name
	})
	IgnorePackageDB = cmpopts.IgnoreFields(claircore.Package{}, ".PackageDB")
)
