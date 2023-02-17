package aws

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
)

func TestVulnerable(t *testing.T) {
	m := &Matcher{}

	testcases := []struct {
		name   string
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		want   bool
	}{
		{
			name: "unfixed same arch",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "10:3.1.0-8.amzn2.0.8",
					Arch:    "noarch",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Arch: "noarch",
				},
				FixedInVersion: "",
				ArchOperation:  claircore.OpEquals,
			},
			want: true,
		},
		{
			name: "unfixed different arch",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "10:3.1.0-8.amzn2.0.8",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Arch: "noarch",
				},
				FixedInVersion: "",
				ArchOperation:  claircore.OpEquals,
			},
			want: false,
		},
		{
			name: "fixed same arch",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "10:3.1.0-8.amzn2.0.8",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Arch: "x86_64",
				},
				FixedInVersion: "10:3.1.0-9.amzn2.0.8",
				ArchOperation:  claircore.OpEquals,
			},
			want: true,
		},
		{
			name: "fixed unaffected arch",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "10:3.1.0-8.amzn2.0.8",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Arch: "noarch",
				},
				FixedInVersion: "10:3.1.0-9.amzn2.0.8",
				ArchOperation:  claircore.OpEquals,
			},
			want: false,
		},
		{
			name: "fixed unaffected version",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "10:3.1.0-9.amzn2.0.8",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Arch: "x86_64",
				},
				FixedInVersion: "9:3.1.0-9.amzn2.0.8",
				ArchOperation:  claircore.OpEquals,
			},
			want: false,
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			got, err := m.Vulnerable(context.Background(), testcase.record, testcase.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.want) {
				t.Error(cmp.Diff(got, testcase.want))
			}
		})
	}
}
