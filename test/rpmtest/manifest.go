package rpmtest

import (
	stdcmp "cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

type Manifest struct {
	RPM []ManifestRPM `json:"rpms"`
}

/*
Example JSON object:

	{
	  "architecture": "s390x",
	  "gpg": "199e2f91fd431d51",
	  "name": "perl-Encode",
	  "nvra": "perl-Encode-2.97-3.el8.s390x",
	  "release": "3.el8",
	  "srpm_name": "perl-Encode",
	  "srpm_nevra": "perl-Encode-4:2.97-3.el8.src",
	  "summary": "Character encodings in Perl",
	  "version": "2.97"
	}
*/

type ManifestRPM struct {
	Name           string `json:"name"`
	Epoch          string `json:"epoch,omitempty"` // Not in Red Hat-provided manifests.
	Version        string `json:"version"`
	Release        string `json:"release"`
	Architecture   string `json:"architecture"`
	NEVRA          string `json:"nevra"` // Sometimes in Red Hat-provided manifests?
	SourceNEVRA    string `json:"srpm_nevra"`
	SourceName     string `json:"srpm_name"`
	GPG            string `json:"gpg"`
	Module         string `json:"module,omitempty"`          // Not in Red Hat-provided manifests.
	RepositoryHint string `json:"_repositoryhint,omitempty"` // Not in Red Hat-provided manifests.
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
	slices.SortFunc(m.RPM, func(a, b ManifestRPM) int {
		return strings.Compare(a.Name, b.Name)
	})

	for n, rpm := range m.RPM {
		pv, err := rpmver.Parse(stdcmp.Or(
			rpm.NEVRA,
			fmt.Sprintf("%s-%s:%s-%s.%s",
				rpm.Name, stdcmp.Or(rpm.Epoch, "0"), rpm.Version, rpm.Release, rpm.Architecture)))
		if err != nil {
			t.Errorf("#%03d: unable to determine version: %v", n, err)
			continue
		}
		// Newer images produced from Konflux shove all the source information
		// into the SourceName and omit the SourceNEVRA. Try both.
		//
		// This sometimes has ".rpm" on it?
		sv, err := rpmver.Parse(strings.TrimSuffix(stdcmp.Or(rpm.SourceNEVRA, rpm.SourceName), ".rpm"))
		if err != nil {
			t.Errorf("#%03d: unable to determine source version: %v", n, err)
			continue
		}

		p := claircore.Package{
			Name:           rpm.Name,
			Version:        pv.EVR(),
			Kind:           "binary",
			Arch:           rpm.Architecture,
			RepositoryHint: url.Values{"key": {rpm.GPG}}.Encode(),
			Module:         rpm.Module,
		}
		srckey := sv.String()
		if s, ok := src[srckey]; ok {
			p.Source = s
		} else {
			idx := len(srcs)
			srcs = append(srcs, claircore.Package{
				Kind:    "source",
				Name:    *sv.Name,
				Version: sv.EVR(),
				Module:  rpm.Module,
			})
			src[srckey] = &srcs[idx]
			p.Source = &srcs[idx]
		}

		out = append(out, &p)
	}

	return out
}

var Options = cmp.Options{
	HintCompare,
	VersionCompare,
	IgnorePackageDB,
	SortPackages,
	ModuleCompare,
}

// RPM Manifest doesn't have checksum information.
//
// It does have keyid information, so cook up a comparison function.
var HintCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".RepositoryHint" },
	cmp.Comparer(func(a, b string) bool {
		av, err := url.ParseQuery(a)
		if err != nil {
			panic(err)
		}
		bv, err := url.ParseQuery(b)
		if err != nil {
			panic(err)
		}
		av.Del("hash")
		bv.Del("hash")
		return cmp.Equal(av.Encode(), bv.Encode())
	}),
)

// Turn [claircore.Package.Version] into [rpmver.Version].
var VersionCompare = cmp.FilterPath(
	func(p cmp.Path) bool {
		l := p.Last()
		return l.Type() == reflect.TypeFor[claircore.Package]() && l.String() == ".Version"
	},
	cmp.Transformer("ParseRPMVersion", func(v string) rpmver.Version {
		println(v)
		p, err := rpmver.Parse(v)
		if err != nil {
			panic(v + ": " + err.Error())
		}
		return p
	}),
)

// ModuleCompare allows one of the reported modules to be the empty string.
// This is needed because of [STONEBLD-1472].
//
// [STONEBLD-1472]: https://issues.redhat.com/browse/STONEBLD-1472
var ModuleCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".Module" },
	cmp.FilterValues(
		func(a, b string) bool { return a != "" && b == "" || a == "" && b != "" },
		cmp.Ignore(),
	),
)

// Does what it says on the tin.
var (
	SortPackages = cmpopts.SortSlices(func(a, b *claircore.Package) bool {
		return a.Name < b.Name
	})
	IgnorePackageDB = cmpopts.IgnoreFields(claircore.Package{}, ".PackageDB")
)
