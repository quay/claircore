package java

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
)

func TestMatcher(t *testing.T) {
	m := &matcher{}
	t.Skip("todo")

	_ = m
}

func TestVulnerable(t *testing.T) {
	matcher := &matcher{}

	testcases := []struct {
		name   string
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		want   bool
	}{
		{
			name: "pkg1",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache .openmeetings :openmeetings-parent",
					Version: "3.2.3",
					Kind:    "binary",
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache .openmeetings :openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "3.2.0+3.3.0",
			},
			want: true,
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
				FixedInVersion: "4.9.11",
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
				FixedInVersion: "LastAffected:1.9.3",
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
				FixedInVersion: "LastAffected:1.9.3",
			},
			want: false,
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
