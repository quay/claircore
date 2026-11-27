package vex

import (
	"log/slog"
	"math"
	"strconv"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/toolkit/types"
)

// fixedContainerAssertions preserves the fixed side of an OCI version boundary.
// The ordinary binary rule still identifies vulnerable older builds. A separate
// ancestry rule lets consumers reconcile language findings for the fixed image's
// contents without extending that assessment to software added in later layers.
func fixedContainerAssertions(vs []*claircore.Vulnerability) []*claircore.Vulnerability {
	var out []*claircore.Vulnerability
	for _, v := range vs {
		if v.Invert || v.Repo == nil || v.Repo.Key != rhcc.RepositoryKey || v.FixedInVersion == "" {
			continue
		}
		r, err := fixedAssertionRange(v.FixedInVersion)
		if err != nil {
			slog.Warn("cannot create fixed container assessment", "version", v.FixedInVersion, "reason", err)
			continue
		}
		assertion := *v
		pkg := *v.Package
		pkg.Kind = types.AncestryPackage
		assertion.Package = &pkg
		assertion.Invert = true
		assertion.Range = r
		out = append(out, &assertion)
	}
	return out
}

func fixedAssertionRange(fixed string) (*claircore.Range, error) {
	v, err := rhctag.Parse(fixed)
	if err != nil {
		return nil, err
	}
	r := &claircore.Range{Lower: v.Version(true), Upper: v.Version(false)}
	if _, err := strconv.ParseUint(fixed, 10, 31); err == nil {
		// Konflux timestamps are ordered build identifiers, not minor series.
		// Later timestamps must reach the matcher, which checks the exact value.
		r.Upper = (&rhctag.Version{Major: math.MaxInt32}).Version(false)
	}
	return r, nil
}
