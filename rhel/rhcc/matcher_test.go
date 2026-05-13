package rhcc

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestVulnerable(t *testing.T) {
	t.Parallel()

	type testcase struct {
		name           string
		packageVersion string
		fixedInVersion string
		repoCPE        cpe.WFN
		vulnRepoCPE    cpe.WFN
		want           bool
	}
	table := []testcase{
		{
			name:           "TimestampOlder",
			packageVersion: "1740000000",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           true,
		},
		{
			name:           "TimestampNewer",
			packageVersion: "1744596866",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TimestampEqual",
			packageVersion: "1742843776",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TimestampUnfixed",
			packageVersion: "1742843776",
			fixedInVersion: "",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           true,
		},
		{
			name:           "TagOlder",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			want:           true,
		},
		{
			name:           "TagNewer",
			packageVersion: "v3.5.9-2",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			want:           false,
		},
		{
			name:           "TagUnfixed",
			packageVersion: "v3.5.9-2",
			fixedInVersion: "",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			want:           true,
		},
		{
			name:           "TagCPEMismatch",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift:4::el8"),
			want:           false,
		},
	}

	var m matcher
	ctx := test.Logging(t)
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: tc.packageVersion,
				},
				Repository: &claircore.Repository{
					Key:  RepositoryKey,
					Name: tc.repoCPE.String(),
					CPE:  tc.repoCPE,
				},
			}
			vuln := &claircore.Vulnerability{
				Package:        &claircore.Package{},
				FixedInVersion: tc.fixedInVersion,
				Repo: &claircore.Repository{
					Key:  RepositoryKey,
					Name: tc.vulnRepoCPE.String(),
					CPE:  tc.vulnRepoCPE,
				},
			}
			got, err := m.Vulnerable(ctx, record, vuln)
			if err != nil {
				t.Error(err)
			}
			if got != tc.want {
				t.Errorf("%q failed: Vulnerable(%q, %q) = %v, want %v",
					tc.name, tc.packageVersion, tc.fixedInVersion, got, tc.want)
			}
		})
	}
}
