package rhcc

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestMatcherVulnerable(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

	type testcase struct {
		name           string
		packageVersion string
		fixedInVersion string
		repo           *claircore.Repository
		vulnRepo       *claircore.Repository
		invert         bool
		want           bool
	}
	table := []testcase{
		{
			name:           "TimestampOlder",
			packageVersion: "1740000000",
			fixedInVersion: "1742843776",
			repo:           cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           true,
		},
		{
			name:           "TimestampNewer",
			packageVersion: "1744596866",
			fixedInVersion: "1742843776",
			repo:           cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TimestampEqual",
			packageVersion: "1742843776",
			fixedInVersion: "1742843776",
			repo:           cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TagOlder",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repo:           cpeRepo("cpe:/a:redhat:quay:3::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:quay:3::el8"),
			want:           true,
		},
		{
			name:           "GoldenRepoTagOlder",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.6-1",
			repo:           &GoldRepo,
			vulnRepo:       &GoldRepo,
			want:           true,
		},
		{
			name:           "TagNewer",
			packageVersion: "v3.5.9-2",
			fixedInVersion: "v3.5.7-8",
			repo:           cpeRepo("cpe:/a:redhat:quay:3::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:quay:3::el8"),
			want:           false,
		},
		{
			name:           "GoldenRepoTagNewer",
			packageVersion: "v3.5.7-1",
			fixedInVersion: "v3.5.6-1",
			repo:           &GoldRepo,
			vulnRepo:       &GoldRepo,
			want:           false,
		},
		{
			name:           "TagCPEMismatch",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repo:           cpeRepo("cpe:/a:redhat:quay:3::el8"),
			vulnRepo:       cpeRepo("cpe:/a:redhat:openshift:4::el8"),
			want:           false,
		},
		{
			name:           "GoldenRepoInverted",
			packageVersion: "7.0.3-13",
			repo:           &GoldRepo,
			vulnRepo:       &GoldRepo,
			invert:         true,
			want:           true,
		},
	}

	var m matcher
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: tc.packageVersion,
				},
				Repository: tc.repo,
			}
			vuln := &claircore.Vulnerability{
				Invert:         tc.invert,
				FixedInVersion: tc.fixedInVersion,
				Repo:           tc.vulnRepo,
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

func cpeRepo(s string) *claircore.Repository {
	w := cpe.MustUnbind(s)
	return &claircore.Repository{
		Key:  RepositoryKey,
		Name: w.String(),
		CPE:  w,
	}
}
