package test

import (
	stdcmp "cmp"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
)

// CompareDigests allows for comparing [claircore.Digest] objects.
var CompareDigests = cmp.Options{
	cmp.Transformer("MarshalDigest", marshalDigest),
	cmp.Transformer("MarshalDigestPointer", marshalDigestPointer),
}

// CompareVulnerabilityReports allows for comparing
// [claircore.VulnerabilityReport] objects.
var CompareVulnerabilityReports = cmp.Options{
	cmp.FilterPath(isVulnerabilityReportField("Packages"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("Distributions"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("Repositories"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("Environments"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("Vulnerabilities"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("PackageVulnerabilities"), vulnerabilityReportMap),
	cmp.FilterPath(isVulnerabilityReportField("Enrichments"), vulnerabilityReportMap),
}

// CmpOptions is a bundle of [cmp.Option] for [claircore] types.
var CmpOptions = cmp.Options{
	CompareDigests,
	CompareVulnerabilityReports,
}

var vulnerabilityReportMap = cmp.Options{
	cmpopts.SortMaps(stdcmp.Less[string]),
	cmpopts.EquateEmpty(),
}

func marshalDigest(d claircore.Digest) string         { return marshalDigestPointer(&d) }
func marshalDigestPointer(d *claircore.Digest) string { return d.String() }

func isVulnerabilityReportField(n string) func(cmp.Path) bool {
	return func(p cmp.Path) bool {
		if len(p) >= 2 && p.Index(-2).Type() == reflect.TypeOf(claircore.VulnerabilityReport{}) {
			sf, ok := p.Index(-1).(cmp.StructField)
			return ok && sf.Name() == n
		}
		return false
	}
}
