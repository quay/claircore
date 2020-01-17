package alpine

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/log"
)

var V3_10_community_truncated_vulns = []*claircore.Vulnerability{
	{
		Name:           "CVE-2018-20187",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20187",
		FixedInVersion: "2.9.0-r0",
		Package: &claircore.Package{
			Name: "botan",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2018-12435",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12435",
		FixedInVersion: "2.7.0-r0",
		Package: &claircore.Package{
			Name: "botan",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2018-9860",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9860",
		FixedInVersion: "2.6.0-r0",
		Package: &claircore.Package{
			Name: "botan",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2018-9127",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9127",
		FixedInVersion: "2.5.0-r0",
		Package: &claircore.Package{
			Name: "botan",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2019-9929",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9929",
		FixedInVersion: "3.12.2-r0",
		Package: &claircore.Package{
			Name: "cfengine",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2017-6949",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6949",
		FixedInVersion: "4.12.0-r3",
		Package: &claircore.Package{
			Name: "chicken",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2017-9334",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9334",
		FixedInVersion: "4.12.0-r2",
		Package: &claircore.Package{
			Name: "chicken",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2016-6830",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6830",
		FixedInVersion: "4.11.1-r0",
		Package: &claircore.Package{
			Name: "chicken",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
	{
		Name:           "CVE-2016-6831",
		Links:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6831",
		FixedInVersion: "4.11.1-r0",
		Package: &claircore.Package{
			Name: "chicken",
		},
		Dist: &claircore.Distribution{
			VersionCodeName: "community",
			VersionID:       "v3.10",
			Version:         "v3.10",
			DID:             "alpine",
			Name:            "Alpine Linux",
			PrettyName:      "Alpine Linux v3.10",
		},
	},
}

func TestParser(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var table = []struct {
		release  Release
		repo     Repo
		testFile string
		expected []*claircore.Vulnerability
	}{
		{
			release:  V3_10,
			repo:     Community,
			testFile: "v3_10_community_truncated.yaml",
			expected: V3_10_community_truncated_vulns,
		},
	}

	for _, test := range table {
		t.Run(test.testFile, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)

			path := fmt.Sprintf("testdata/%s", test.testFile)
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("failed to open test data: %v", path)
			}

			u, err := NewUpdater(test.release, test.repo)
			if err != nil {
				t.Fatalf("failed to create updater: %v", err)
			}
			vulns, err := u.Parse(ctx, f)
			if err != nil {
				t.Fatalf("failed to parse xml: %v", err)
			}

			sort.SliceStable(vulns,
				func(i, j int) bool { return vulns[i].Name < vulns[j].Name })
			sort.SliceStable(test.expected,
				func(i, j int) bool { return test.expected[i].Name < test.expected[j].Name })

			if !cmp.Equal(vulns, test.expected) {
				diff := cmp.Diff(vulns, test.expected)
				t.Fatalf("security databases were not equal: \n%v", diff)
			}
		})
	}
}
