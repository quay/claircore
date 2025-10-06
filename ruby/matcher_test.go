package ruby

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestVulnerable(t *testing.T) {
	matcher := &Matcher{}

	testcases := []struct {
		name   string
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		want   bool
	}{
		{
			name: "bootstrap affected",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bootstrap",
					Version: "3.2.9",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-7mvr-5x2g-wfc8",
				Description: "Bootstrap Cross-site Scripting vulnerability",
				Package: &claircore.Package{
					Name:           "bootstrap",
					RepositoryHint: "RubyGems",
				},
				FixedInVersion: "fixed=4.1.2",
			},
			want: true,
		},
		{
			name: "bootstrap unaffected",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bootstrap",
					Version: "4.1.2",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-7mvr-5x2g-wfc8",
				Description: "Bootstrap Cross-site Scripting vulnerability",
				Package: &claircore.Package{
					Name:           "bootstrap",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "fixed=4.1.2-alpha",
			},
			want: false,
		},
		{
			name: "openshift-origin-node unfixed",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "openshift-origin-node",
					Version: "1.3.2",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2c25-xfpq-8n9r",
				Description: "Ruby gem openshift-origin-node before 2014-02-14 does not contain a cronjob timeout which could result in a denial of service in cron.daily and cron.weekly.",
				Package: &claircore.Package{
					Name:           "openshift-origin-node",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "lastAffected=1.3.3",
			},
			want: true,
		},
		{
			name: "openshift-origin-node unfixed again",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "openshift-origin-node",
					Version: "1.3.3",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2c25-xfpq-8n9r",
				Description: "Ruby gem openshift-origin-node before 2014-02-14 does not contain a cronjob timeout which could result in a denial of service in cron.daily and cron.weekly.",
				Package: &claircore.Package{
					Name:           "openshift-origin-node",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "lastAffected=1.3.3",
			},
			want: true,
		},
		{
			name: "dependabot-omnibus affected",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "dependabot-omnibus",
					Version: "0.120.0.beta2",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-23f7-99jx-m54r",
				Description: "Remote code execution in dependabot-core branch names when cloning",
				Package: &claircore.Package{
					Name:           "dependabot-omnibus",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "fixed=0.125.1&introduced=0.119.0.beta1",
			},
			want: true,
		},
		{
			name: "dependabot-omnibus unaffected",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "dependabot-omnibus",
					Version: "0.119.0-alpha3",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-23f7-99jx-m54r",
				Description: "Remote code execution in dependabot-core branch names when cloning",
				Package: &claircore.Package{
					Name:           "dependabot-omnibus",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "fixed=0.125.1&introduced=0.119.0-beta1",
			},
			want: false,
		},
		{
			name: "dependabot-omnibus no upper bound",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "dependabot-omnibus",
					Version: "0.119.0",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-23f7-99jx-m54r",
				Description: "Remote code execution in dependabot-core branch names when cloning",
				Package: &claircore.Package{
					Name:           "dependabot-omnibus",
					RepositoryHint: "rubygems",
				},
				FixedInVersion: "introduced=0.119.0-beta1",
			},
			want: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			got, err := matcher.Vulnerable(context.Background(), testcase.record, testcase.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.want) {
				t.Error(cmp.Diff(got, testcase.want))
			}
		})
	}
}

func TestMatcher(t *testing.T) {
	ctx := test.Logging(t)
	test.RunMatcherTests(ctx, t, "testdata/matcher", new(Matcher))
}
