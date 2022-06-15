package alpine

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var v3_10CommunityTruncatedSecDB = SecurityDB{
	Distroversion: "v3.10",
	Reponame:      "community",
	Urlprefix:     "http://dl-cdn.alpinelinux.org/alpine",
	Apkurl:        "{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
	Packages: []Package{
		{
			Pkg: Details{
				Name: "botan",
				Secfixes: map[string][]string{
					"2.9.0-r0": {"CVE-2018-20187"},
					"2.7.0-r0": {"CVE-2018-12435"},
					"2.6.0-r0": {"CVE-2018-9860"},
					"2.5.0-r0": {"CVE-2018-9127"},
				},
			},
		},
		{
			Pkg: Details{
				Name: "cfengine",
				Secfixes: map[string][]string{
					"3.12.2-r0": {"CVE-2019-9929"},
				},
			},
		},
		{
			Pkg: Details{
				Name: "chicken",
				Secfixes: map[string][]string{
					"4.12.0-r3": {"CVE-2017-6949"},
					"4.12.0-r2": {"CVE-2017-9334"},
					"4.11.1-r0": {"CVE-2016-6830", "CVE-2016-6831"},
				},
			},
		},
	},
}

func TestSecDBParse(t *testing.T) {
	var table = []struct {
		testFile string
		expected SecurityDB
	}{
		{
			testFile: "v3_10_community_truncated.json",
			expected: V3_10_community_truncated_secDB,
		},
	}

	for _, test := range table {
		t.Run(test.testFile, func(t *testing.T) {
			t.Parallel()

			path := fmt.Sprintf("testdata/%s", test.testFile)
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("failed to open test data: %v", path)
			}

			var db SecurityDB
			if err := json.NewDecoder(f).Decode(&db); err != nil {
				t.Fatalf("failed to parse file contents into sec db: %v", err)
			}

			if !cmp.Equal(db, test.expected) {
				diff := cmp.Diff(db, test.expected)
				t.Fatalf("security databases were not equal: \n%v", diff)
			}
		})
	}
}
