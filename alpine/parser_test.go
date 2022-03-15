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

var V3_10_community_truncated_vulns = []*claircore.Vulnerability{
	{
		Name:               "CVE-2018-20187",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20187",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.9.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2018-12435",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12435",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.7.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2018-9860",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9860",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.6.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2018-9127",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9127",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.5.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2019-9929",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9929",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "3.12.2-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "cfengine",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2017-6949",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6949",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.12.0-r3",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2017-9334",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9334",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.12.0-r2",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2016-6830",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6830",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.11.1-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
	{
		Name:               "CVE-2016-6831",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6831",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "4.11.1-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "chicken",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_10),
	},
}

var V3_15_main_truncated_vulns = []*claircore.Vulnerability{
	{
		Name:               "CVE-2017-15873",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15873",
		Updater:            "alpine-main-v3.15-updater",
		FixedInVersion:     "1.27.2-r4",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "busybox",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_15),
	},
	{
		Name:               "CVE-2016-0634",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0634",
		Updater:            "alpine-main-v3.15-updater",
		FixedInVersion:     "4.4.12-r1",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "bash",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_15),
	},
	{
		Name:               "CVE-2017-16544",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16544",
		Updater:            "alpine-main-v3.15-updater",
		FixedInVersion:     "1.27.2-r4",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "busybox",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_15),
	},
	{
		Name:               "CVE-2017-15874",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15874",
		Updater:            "alpine-main-v3.15-updater",
		FixedInVersion:     "1.27.2-r4",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "busybox",
			Kind: claircore.BINARY,
		},
		Dist: releaseToDist(V3_15),
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
			testFile: "v3_10_community_truncated.json",
			expected: V3_10_community_truncated_vulns,
		},
		{
			release:  V3_15,
			repo:     Main,
			testFile: "v3_15_main_truncated.json",
			expected: V3_15_main_truncated_vulns,
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

			u, err := NewUpdater(test.release, test.repo)
			if err != nil {
				t.Fatalf("failed to create updater: %v", err)
			}
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
