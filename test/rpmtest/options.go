package rpmtest

import (
	"net/url"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

// Options is a standard set of [cmp.Options] for working with packages from
// rpm.
var Options = cmp.Options{
	HintCompare,
	VersionCompare,
	IgnorePackageDB,
	SortPackages,
	ModuleCompare,
}

// HintCompare normalizes the claircore-internal "hint".
//
// The RPM manifest doesn't have checksum information. It does have keyid
// information, so normalize down to the common set.
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

// VersionCompare turns a [Package.Version] into [rpmver.Version]. Go-cmp
// produces sensible output on [rpmver.Version] objects.
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
