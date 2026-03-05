package rpm

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

// MatchVulnerable is a function implementing "driver.Matcher.Vulnerable"
// in a common way.
//
// Given a package version "P" and vulnerability "V":
//
//   - If a fixed version "F" is specified in "V", "P < F" is reported.
//   - If a package version "F" is specified in "V", "P <= F" is reported.
//   - If no version is provided in "V", this function compares against an
//     "infinite" version.
//
// In addition to this version comparison, the architectures are compared.
func MatchVulnerable(ctx context.Context, rec *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	p, err := rpmver.Parse(rec.Package.Version)
	if err != nil {
		return false, fmt.Errorf("rpm: unable to parse package version %q: %w",
			rec.Package.Version, err)
	}

	var v rpmver.Version
	cmp := isLTE
	switch {
	case vuln.FixedInVersion != "":
		v, err = rpmver.Parse(vuln.FixedInVersion)
		cmp = isLT
	case vuln.Package.Version != "":
		v, err = rpmver.Parse(vuln.Package.Version)
	default:
		v, err = rpmver.Parse("65535:65535-65535")
	}
	if err != nil {
		return false, fmt.Errorf("rpm: unable to parse vulnerability version %q: %w",
			rec.Package.Version, err)
	}

	return cmp(rpmver.Compare(&p, &v)) && vuln.ArchOperation.Cmp(rec.Package.Arch, vuln.Package.Arch), nil
}

func isLTE(cmp int) bool { return cmp != 1 }
func isLT(cmp int) bool  { return cmp == -1 }
