package npm

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestVulnerable(t *testing.T) {
	ctx := test.Logging(t)
	m := &Matcher{}
	eap := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1")
	eapMajor := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8")
	eap74 := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:7.4")
	quarkus := cpe.MustUnbind("cpe:/a:redhat:quarkus:3")

	record := func(version string, w cpe.WFN) *claircore.IndexRecord {
		return &claircore.IndexRecord{
			Package: &claircore.Package{Name: "js-cookie", Version: version},
			Repository: &claircore.Repository{
				Name: w.String(),
				Key:  RepositoryKey,
				CPE:  w,
			},
		}
	}
	vuln := func(fixed, name string) *claircore.Vulnerability {
		return &claircore.Vulnerability{
			Name:           "CVE-2026-46625",
			FixedInVersion: fixed,
			Repo: &claircore.Repository{
				Name: name,
				Key:  RepositoryKey,
			},
		}
	}

	tests := []struct {
		name   string
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		want   bool
	}{
		{
			name:   "older than fixed",
			record: record("4.1.2", eap),
			vuln:   vuln("4.1.3", eap.String()),
			want:   true,
		},
		{
			name:   "equal to fixed",
			record: record("4.1.3", eap),
			vuln:   vuln("4.1.3", eap.String()),
		},
		{
			name:   "newer than fixed",
			record: record("4.2.0", eap),
			vuln:   vuln("4.1.3", eap.String()),
		},
		{
			name:   "prerelease is older",
			record: record("1.0.0-1", eap),
			vuln:   vuln("1.0.0", eap.String()),
			want:   true,
		},
		{
			name:   "unversioned known_affected",
			record: record("3.0.8", eap),
			vuln:   vuln("", eapMajor.String()),
			want:   true,
		},
		{
			name:   "major CPE pattern",
			record: record("1.0.0", eap),
			vuln:   vuln("", eapMajor.String()),
			want:   true,
		},
		{
			name:   "different minor",
			record: record("1.0.0", eap),
			vuln:   vuln("", eap74.String()),
		},
		{
			name:   "different product",
			record: record("1.0.0", eap),
			vuln:   vuln("", quarkus.String()),
		},
		{
			name:   "empty package version",
			record: record("", eap),
			vuln:   vuln("4.1.3", eap.String()),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.Vulnerable(ctx, tt.record, tt.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Vulnerable() = %v, want %v", got, tt.want)
			}
		})
	}

	if !m.Filter(record("1.0.0", eap)) {
		t.Fatal("npm product record was filtered out")
	}
	javaRepo := &claircore.IndexRecord{Repository: &claircore.Repository{Key: "redhat-java-cpe-repository"}}
	if m.Filter(javaRepo) {
		t.Fatal("Java product record was accepted")
	}
	q := m.Query()
	if len(q) != 1 || q[0] != driver.RepositoryKey {
		t.Fatalf("Query() = %v", q)
	}
}
