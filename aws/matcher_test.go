package aws

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
)

func TestVulnerable(t *testing.T) {
	m := &Matcher{}
	type testcase struct {
		name   string
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		want   bool
	}
	inner := func(testcase *testcase) func(*testing.T) {
		return func(t *testing.T) {
			got, err := m.Vulnerable(context.Background(), testcase.record, testcase.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.want) {
				t.Error(cmp.Diff(got, testcase.want))
			}
		}
	}

	t.Run("Unfixed", func(t *testing.T) {
		testcases := []testcase{
			{
				name: "SameArch",
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
				name: "DifferentArch",
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
		}
		for _, testcase := range testcases {
			t.Run(testcase.name, inner(&testcase))
		}
	})
	t.Run("Fixed", func(t *testing.T) {

		testcases := []testcase{
			{
				name: "SameArch",
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
				name: "UnaffectedArch",
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
				name: "UnaffectedVersion",
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
			t.Run(testcase.name, inner(&testcase))
		}
	})
}
