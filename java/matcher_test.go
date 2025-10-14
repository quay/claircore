package java

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
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		name   string
		want   bool
	}{
		{
			name: "pkg0",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.2.9",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=3.3.0&introduced=3.2.0",
			},
			want: true,
		},
		{
			name: "pkg1",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.3.0",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=3.3.0&introduced=3.2.0",
			},
			want: false,
		},
		{
			name: "pkg2",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.jfinal:jfinal",
					Version: "4.9.0",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2c25-xfpq-8n9r",
				Description: "Cross-site scripting in ¡final",
				Package: &claircore.Package{
					Name:           "com.jfinal:jfinal",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=4.9.11",
			},
			want: true,
		},
		{
			name: "pkg3",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.gitblit:gitblit",
					Version: "1.9.3",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-265-ra62-fahg",
				Description: "Path traversal in Gitblit",
				Package: &claircore.Package{
					Name:           "com.gitblit:gitblit",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=1.9.3",
			},
			want: true,
		},
		{
			name: "pkg4",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.gitblit:gitblit",
					Version: "1.9.4",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-265-ra62-fahg",
				Description: "Path traversal in Gitblit",
				Package: &claircore.Package{
					Name:           "com.gitblit:gitblit",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=1.9.3",
			},
			want: false,
		},
		{
			name: "pkg5",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.3.0",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=3.3.0&introduced=3.2.0",
			},
			want: true,
		},
		{
			name: "pkg6",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.1.9",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=3.3.0&introduced=3.2.0",
			},
			want: false,
		},
		{
			name: "pkg7",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.tiles:tiles-core",
					Version: "3.0.7",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-qw4h-3xjj-84cc",
				Description: "Go look it up: https://osv.dev/vulnerability/GHSA-qw4h-3xjj-84cc",
				Package: &claircore.Package{
					Name:           "org.apache.tiles:tiles-core",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=2.0.0",
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
	test.RunMatcherTests(test.Logging(t), t, "testdata/matcher", new(Matcher))
}
