package rpmtest

import (
	"net/url"
	"reflect"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

// Options is a standard set of [cmp.Options] for working with packages from
// rpm. The passed [testing.TB] is captured, so the returned Options cannot be
// reused across tests.
func Options(t testing.TB) cmp.Options {
	return cmp.Options{
		HintCompare(t),
		VersionTransform(t),
		IgnorePackageDB,
		SortPackages,
		ModuleCompare,
	}
}

// HintCompare normalizes the claircore-internal "hint".
//
// The RPM manifest doesn't have checksum information. It does have keyid
// information, so normalize down to the common set.
func HintCompare(t testing.TB) cmp.Option {
	return cmp.FilterPath(
		func(p cmp.Path) bool { return p.Last().String() == ".RepositoryHint" },
		cmp.Comparer(func(a, b string) bool {
			av, err := url.ParseQuery(a)
			if err != nil {
				t.Errorf("%q: %v", a, err)
			}
			bv, err := url.ParseQuery(b)
			if err != nil {
				t.Errorf("%q: %v", b, err)
			}
			av.Del("hash")
			bv.Del("hash")
			return cmp.Equal(av.Encode(), bv.Encode())
		}),
	)
}

// VersionTransform turns a [Package.Version] into [rpmver.Version]. Go-cmp
// produces sensible output on [rpmver.Version] objects.
func VersionTransform(t testing.TB) cmp.Option {
	var warn sync.Once
	return cmp.FilterPath(
		func(p cmp.Path) bool {
			prev := p.Index(-2)
			cur := p.Last()
			return prev.Type() == reflect.TypeFor[claircore.Package]() &&
				(cur.String() == ".Version" && cur.Type() == reflect.TypeFor[string]())
		},
		cmp.Transformer("ParseRPMVersion", func(v string) rpmver.Version {
			p, err := rpmver.Parse(v)
			if err != nil {
				t.Errorf("%q: %v", v, err)
			}
			if p.Epoch != "" {
				warn.Do(func() {
					t.Log("⚠️\tunable to compare versions with epochs (see https://issues.redhat.com/browse/KONFLUX-7481)")
					t.Log("⚠️\tsetting all epochs to \"0\"")
				})
			}
			p.Epoch = ""
			return p
		}),
	)
}

// ModuleCompare allows one of the reported modules to be the empty string.
// This is needed because of [KONFLUX-7481] (née [STONEBLD-1472]).
//
// [KONFLUX-7481]: https://issues.redhat.com/browse/KONFLUX-7481
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
