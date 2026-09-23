package postgres

import (
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

const cpe23Prefix = "cpe:2.3:"

// mustCPEFS requires a canonical CPE 2.3 formatted string. MustUnbind accepts
// URI bindings as well, and WFN.String() always prints the formatted string,
// so Unbind cannot tell the two forms apart.
func mustCPEFS(t *testing.T, s string) {
	t.Helper()
	if !strings.HasPrefix(s, cpe23Prefix) {
		t.Fatalf("want CPE 2.3 formatted string, got %q", s)
	}
	if got := cpe.MustUnbind(s).String(); got != s {
		t.Fatalf("not canonical FS: %q round-trips to %q", s, got)
	}
}

// sqlCPEKept reports whether Get's CPE predicate would keep repoName for recordFS.
// A field matches when it is "*", equal to the record ignoring case, or contains
// "*" or "?". The version field also matches when the record version starts with
// the stored version. Both arguments are the text SQL sees.
func sqlCPEKept(recordFS, repoName string) bool {
	rec := cpe.MustUnbind(recordFS)
	parts := strings.Split(repoName, ":")
	for a := range cpe.NumAttr {
		field := ""
		if idx := a + 2; idx < len(parts) {
			field = parts[idx]
		}
		if strings.ContainsAny(field, "*?") {
			continue
		}
		if strings.EqualFold(field, rec.Attr[a].String()) {
			continue
		}
		if a == int(cpe.Version) && strings.HasPrefix(rec.Attr[cpe.Version].String(), field) {
			continue
		}
		return false
	}
	return true
}

func TestVEXFeedCPERepresentative(t *testing.T) {
	// Pairs are CPE 2.3 formatted-string values: VEX product_identification_helper.cpe
	// after Unbind, which is what lands in repo_name and on the index record.
	tests := []struct {
		name, record, vuln string
		want               bool
	}{
		{"ocp short version", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift:4:*:*:*:*:*:*:*", true},
		{"ocp dotted version", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift:4.13:*:*:*:*:*:*:*", true},
		{"ocp same edition", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", true},
		{"ocp other minor", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift:4.12:*:el8:*:*:*:*:*", false},
		{"ocp v3", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift:3:*:*:*:*:*:*:*", false},
		{"ocp vs openshift_ai", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:openshift_ai:2.16:*:el8:*:*:*:*:*", false},
		{"el8 os short", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*", true},
		{"el8 os same", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", true},
		{"el8 vs el9 os", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*", false},
		{"os vs appstream part", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", "cpe:2.3:a:redhat:enterprise_linux:8:*:appstream:*:*:*:*:*", false},
		{"el9 appstream short", "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*", "cpe:2.3:a:redhat:enterprise_linux:9:*:*:*:*:*:*:*", true},
		{"el9 appstream same", "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*", "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*", true},
		{"el9 appstream vs crb", "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*", "cpe:2.3:a:redhat:enterprise_linux:9:*:crb:*:*:*:*:*", false},
		{"el10 dotted vs short", "cpe:2.3:o:redhat:enterprise_linux:10.1:*:*:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:10:*:*:*:*:*:*:*", true},
		{"eus vs main os", "cpe:2.3:o:redhat:rhel_eus:9.4:*:baseos:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*", false},
		{"eus same", "cpe:2.3:o:redhat:rhel_eus:9.4:*:baseos:*:*:*:*:*", "cpe:2.3:o:redhat:rhel_eus:9.4:*:baseos:*:*:*:*:*", true},
		{"aap nover pattern", "cpe:2.3:a:redhat:ansible_automation_platform:2.3:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:ansible_automation_platform:*:*:*:*:*:*:*:*", true},
		{"aap short version", "cpe:2.3:a:redhat:ansible_automation_platform:2.3:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:ansible_automation_platform:2:*:*:*:*:*:*:*", true},
		{"aap developer vs aap", "cpe:2.3:a:redhat:ansible_automation_platform_developer:2.3:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:ansible_automation_platform:*:*:*:*:*:*:*:*", false},
		{"aap inside vs aap", "cpe:2.3:a:redhat:ansible_automation_platform_inside:2.3:*:el9:*:*:*:*:*", "cpe:2.3:a:redhat:ansible_automation_platform:2.3:*:el9:*:*:*:*:*", false},
		{"acm short version", "cpe:2.3:a:redhat:acm:2.10:*:el9:*:*:*:*:*", "cpe:2.3:a:redhat:acm:2:*:*:*:*:*:*:*", true},
		{"3scale short version", "cpe:2.3:a:redhat:3scale_amp:2.11:*:el8:*:*:*:*:*", "cpe:2.3:a:redhat:3scale_amp:2:*:*:*:*:*:*:*", true},
		{"a_mq_clients same", "cpe:2.3:a:redhat:a_mq_clients:2:*:el7:*:*:*:*:*", "cpe:2.3:a:redhat:a_mq_clients:2:*:el7:*:*:*:*:*", true},
		{"convert2rhel nover", "cpe:2.3:a:redhat:convert2rhel:*:*:*:*:*:*:*:*", "cpe:2.3:a:redhat:convert2rhel:*:*:*:*:*:*:*:*", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustCPEFS(t, tt.record)
			mustCPEFS(t, tt.vuln)
			if got := sqlCPEKept(tt.record, tt.vuln); got != tt.want {
				t.Fatalf("kept=%v want=%v\n record %s\n vuln   %s", got, tt.want, tt.record, tt.vuln)
			}
		})
	}
}

func TestSQLKeepsCompareSupersets(t *testing.T) {
	el8 := "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*"
	el10 := "cpe:2.3:o:redhat:enterprise_linux:10.0:*:baseos:*:*:*:*:*"
	ocp := "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*"
	mustCPEFS(t, el8)
	mustCPEFS(t, el10)
	mustCPEFS(t, ocp)

	tests := []struct {
		name, record, repo string
		keep, superset     bool
		compare            bool
	}{
		{
			name:     "version any with a concrete edition",
			record:   el10,
			repo:     "cpe:2.3:o:redhat:enterprise_linux:*:*:baseos:*:*:*:*:*",
			keep:     true,
			superset: true,
			compare:  true,
		},
		{
			name:    "version any does not cross editions",
			record:  el10,
			repo:    "cpe:2.3:o:redhat:enterprise_linux:*:*:appstream:*:*:*:*:*",
			compare: true,
		},
		{
			name:     "version glob keeps a later concrete attribute",
			record:   ocp,
			repo:     "cpe:2.3:a:redhat:openshift:4.*:*:el8:*:*:*:*:*",
			keep:     true,
			superset: true,
			compare:  true,
		},
		{
			name:    "question-mark glob is kept for Compare to reject",
			record:  ocp,
			repo:    "cpe:2.3:a:redhat:openshift:4.1?:*:el8:*:*:*:*:*",
			keep:    true,
			compare: true,
		},
		{
			name:    "short version matches the version field",
			record:  ocp,
			repo:    "cpe:2.3:a:redhat:openshift:4:*:*:*:*:*:*:*",
			keep:    true,
			compare: true,
		},
		{
			name:    "concrete version 8 does not match 10.0",
			record:  el10,
			repo:    el8,
			compare: true,
		},
		{
			name:   "case difference is an attribute match",
			record: el8,
			repo:   "cpe:2.3:o:redhat:Enterprise_Linux:8:*:baseos:*:*:*:*:*",
			keep:   true,
		},
		{
			name:   "a later binding header still matches attributes",
			record: el8,
			repo:   "cpe:2.4:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*",
			keep:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustCPEFS(t, tt.record)
			if tt.compare {
				mustCPEFS(t, tt.repo)
				got := cpe.Compare(cpe.MustUnbind(tt.repo), cpe.MustUnbind(tt.record)).IsSuperset()
				if got != tt.superset {
					t.Fatalf("Compare.IsSuperset=%v want=%v", got, tt.superset)
				}
			}
			if tt.superset && !tt.keep {
				t.Fatalf("Compare accepts this pair and SQL drops it")
			}
			if got := sqlCPEKept(tt.record, tt.repo); got != tt.keep {
				t.Fatalf("kept=%v want=%v", got, tt.keep)
			}
		})
	}
}

func TestCPECompareURIIsNotWhatSQLSees(t *testing.T) {
	// VEX documents store URI bindings such as cpe:/a:redhat:openshift:4.
	// repo_name and the Get predicate store formatted strings. Unbind converts
	// that URI into a formatted string that matches the record below; the SQL
	// comparison uses the URI text unchanged, so it must not match.
	record := "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*"
	uri := "cpe:/a:redhat:openshift:4"
	mustCPEFS(t, record)
	if strings.HasPrefix(uri, cpe23Prefix) {
		t.Fatalf("fixture is not URI: %q", uri)
	}
	if sqlCPEKept(record, uri) {
		t.Fatalf("URI repo_name must not satisfy the FS SQL predicates")
	}
	// The record side is the WFN, so Unbind has already turned the URI into
	// attributes. The predicate never compares the URI text as the record.
}

func TestCPECompareEmptyRecord(t *testing.T) {
	if got := cpeCompareExpressions(nil); got != nil {
		t.Fatalf("nil record: %v", got)
	}
	if got := cpeCompareExpressions(&claircore.IndexRecord{}); got != nil {
		t.Fatalf("nil repo: %v", got)
	}
	if got := cpeCompareExpressions(&claircore.IndexRecord{Repository: &claircore.Repository{}}); got != nil {
		t.Fatalf("empty CPE: %v", got)
	}
}
