package alpine

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

var dist310 = release{3, 10}.Distribution()

var v3_10CommunityTruncatedVulns = []*claircore.Vulnerability{
	{
		Name:               "CVE-2018-20187",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20187",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.9.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2018-12435",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12435",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.7.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2018-9860",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9860",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.6.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2018-9127",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9127",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.5.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2019-9929",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9929",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "3.12.2-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "cfengine",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2017-6949",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6949",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.12.0-r3",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2017-9334",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9334",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.12.0-r2",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2016-6830",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6830",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.11.1-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
	{
		Name:               "CVE-2016-6831",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6831",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.11.1-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.SOURCE,
		},
		Dist: dist310,
	},
}

func TestParser(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var table = []struct {
		release  release
		repo     string
		testFile string
		expected []*claircore.Vulnerability
	}{
		{
			release:  release{3, 10},
			repo:     "community",
			testFile: "fetch/v3.10/community.json",
			expected: v3_10CommunityTruncatedVulns,
		},
	}

	for _, test := range table {
		t.Run(test.testFile, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)

			path := fmt.Sprintf("testdata/%s", test.testFile)
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("failed to open test data: %v", path)
			}

			u := &updater{release: test.release, repo: test.repo}
			vulns, err := u.Parse(ctx, f)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
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
