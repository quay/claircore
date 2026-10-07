package java

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRedHatMatcherVulnerable(t *testing.T) {
	ctx := test.Logging(t)
	m := &RedHatMatcher{}
	quarkus := cpe.MustUnbind("cpe:/a:redhat:quarkus:3.33")
	quarkusEl := cpe.MustUnbind("cpe:/a:redhat:quarkus:3.33::el8")
	quarkusMajor := cpe.MustUnbind("cpe:/a:redhat:quarkus:3")
	eap := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1")
	eapMajor := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8")

	record := func(version string, w cpe.WFN) *claircore.IndexRecord {
		return &claircore.IndexRecord{
			Package: &claircore.Package{Name: "io.netty:netty-codec", Version: version},
			Repository: &claircore.Repository{
				Name: w.String(),
				Key:  RepositoryKey,
				CPE:  w,
			},
		}
	}
	vuln := func(fixed string, name string) *claircore.Vulnerability {
		return &claircore.Vulnerability{
			Name:           "CVE-2026-59889",
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
			record: record("4.1.100.Final-redhat-00001", quarkus),
			vuln:   vuln("4.1.115.Final-redhat-00002", quarkus.String()),
			want:   true,
		},
		{
			name:   "equal to fixed",
			record: record("4.1.115.Final-redhat-00002", quarkus),
			vuln:   vuln("4.1.115.Final-redhat-00002", quarkus.String()),
		},
		{
			name:   "newer than fixed",
			record: record("4.1.120.Final-redhat-00001", quarkus),
			vuln:   vuln("4.1.115.Final-redhat-00002", quarkus.String()),
		},
		{
			name:   "unversioned known_affected",
			record: record("9.9.9", eap),
			vuln:   vuln("", eapMajor.String()),
			want:   true,
		},
		{
			name:   "major CPE pattern",
			record: record("1.0", quarkus),
			vuln:   vuln("", quarkusMajor.String()),
			want:   true,
		},
		{
			name:   "edition makes the advisory narrower",
			record: record("1.0", quarkus),
			vuln:   vuln("", quarkusEl.String()),
		},
		{
			name:   "different product",
			record: record("1.0", quarkus),
			vuln:   vuln("", eapMajor.String()),
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

	if !m.Filter(record("1.0", quarkus)) {
		t.Fatal("product CPE record was filtered out")
	}
	central := &claircore.IndexRecord{Repository: &claircore.Repository{Name: "maven"}}
	if m.Filter(central) {
		t.Fatal("Maven Central record was accepted")
	}
	q := m.Query()
	if len(q) != 1 || q[0] != driver.RepositoryKey {
		t.Fatalf("Query() = %v", q)
	}
}
