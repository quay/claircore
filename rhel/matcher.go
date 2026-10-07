package rhel

import (
	"context"
	"log/slog"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Matcher implements [driver.Matcher].
type Matcher struct {
	ignoreUnpatched bool
}

// BUG(hank) [Dynamic modules] are unsupported.
//
// Modules are identified by a Name-Stream-Version-Context (NSVC) string. In
// standard static modules, the "Name" and "Stream" values form a namespace for
// one lineage of rpm packages. In a dynamic module, there are instead multiple
// lineages in the same stream, and one must inspect the module metadata and use
// dependency solving information to construct these lineages.
//
// This is not possible within the constraints of a [driver.Matcher] implementation.
//
// [Dynamic modules]: https://docs.fedoraproject.org/en-US/modularity/core-concepts/upgrade-paths/#_dynamic_context

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "rhel"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == repositoryKey
}

// Query implements [driver.Matcher].
func (m *Matcher) Query() []driver.MatchConstraint {
	mcs := []driver.MatchConstraint{driver.PackageModule, driver.RepositoryKey}
	if m.ignoreUnpatched {
		mcs = append(mcs, driver.HasFixedInVersion)
	}
	return mcs
}

// IsCPESubstringMatch is a Red Hat specific hack that handles the "CPE
// patterns" in the VEX data. For historical/unfathomable reasons, Red Hat
// doesn't use the syntax defined in the Matching Expression spec. For example,
// "cpe:/a:redhat:openshift:4" is expected to match
// "cpe:/a:redhat:openshift:4.13::el8".
//
// This is defined (citation needed) to be a substring match on the "pattern"
// and "target" CPEs. Attributes other than version use the normal superset
// comparison. The version matches when it is equal or the record continues
// with ".", so version 4 matches 4.13 and version 1 does not match 10. A dot
// in another attribute, such as a product node.js, does not match.
//
// TODO(crozzy) Remove once RH VEX data updates CPEs with standard matching
// expressions.
func IsCPESubstringMatch(recordCPE cpe.WFN, vulnCPE cpe.WFN) bool {
	p := vulnCPE.Attr[cpe.Version]
	r := recordCPE.Attr[cpe.Version]
	// A dotted extension of the pattern version is the same version for this hack.
	if p.Kind == cpe.ValueSet && r.Kind == cpe.ValueSet {
		rest, ok := strings.CutPrefix(strings.ToLower(r.String()), strings.ToLower(p.String()))
		if ok && strings.HasPrefix(rest, ".") {
			vulnCPE.Attr[cpe.Version] = r
		}
	}
	return cpe.Compare(vulnCPE, recordCPE).IsSuperset()
}

// Vulnerable implements [driver.Matcher].
//
// Vulnerable will interpret the [claircore.Vulnerability].Repo.CPE as a CPE
// match expression, and to be considered vulnerable, the relationship between
// [claircore.IndexRecord].Repository.CPE and the
// [claircore.Vulnerability].Repo.CPE needs to be a CPE Name Comparison Relation
// of SUPERSET(⊇)(Source is a superset or equal to the target).
//
// See: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf Section 6.2.
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.Repo == nil || record.Repository == nil || vuln.Repo.Key != repositoryKey {
		return false, nil
	}
	var err error
	// This conversion has to be done because our current data model doesn't
	// support the claircore.Vulnerability.Repo.CPE field.
	vuln.Repo.CPE, err = cpe.Unbind(vuln.Repo.Name)
	if err != nil {
		slog.WarnContext(ctx, "unable to unbind repo CPE", "reason", err, "vulnerability name", vuln.Name)
		return false, nil
	}
	if !IsCPESubstringMatch(record.Repository.CPE, vuln.Repo.CPE) {
		return false, nil
	}

	return rpm.MatchVulnerable(ctx, record, vuln)
}
