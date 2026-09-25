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

// sqlCPESubstring reports whether Get would keep repoName for recordFS,
// mirroring cpeSubstringExpressions (product LIKE then starts_with + rtrim).
// Both arguments are the text SQL sees: vuln.repo_name and
// IndexRecord.Repository.CPE.String(). They are not Unbound first.
func sqlCPESubstring(recordFS, repoName string) bool {
	w := cpe.MustUnbind(recordFS)
	if prefix := cpeProductPrefix(w); prefix != "" && !strings.HasPrefix(repoName, prefix) {
		return false
	}
	return strings.HasPrefix(recordFS, strings.TrimRight(repoName, ":*"))
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
			if got := sqlCPESubstring(tt.record, tt.vuln); got != tt.want {
				t.Fatalf("sql=%v want=%v\n record %s\n vuln   %s", got, tt.want, tt.record, tt.vuln)
			}
		})
	}
}

func TestCPESubstringURIIsNotWhatSQLSees(t *testing.T) {
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
	if sqlCPESubstring(record, uri) {
		t.Fatalf("URI repo_name must not satisfy the FS SQL predicates")
	}
	if sqlCPESubstring(uri, "cpe:2.3:a:redhat:openshift:4:*:*:*:*:*:*:*") {
		t.Fatalf("URI record must not satisfy the FS SQL predicates")
	}
}

func TestCPESubstringEmptyRecord(t *testing.T) {
	if got := cpeSubstringExpressions(nil); got != nil {
		t.Fatalf("nil record: %v", got)
	}
	if got := cpeSubstringExpressions(&claircore.IndexRecord{}); got != nil {
		t.Fatalf("nil repo: %v", got)
	}
	if got := cpeSubstringExpressions(&claircore.IndexRecord{Repository: &claircore.Repository{}}); got != nil {
		t.Fatalf("empty CPE: %v", got)
	}
}
