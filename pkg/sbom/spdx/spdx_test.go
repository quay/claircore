package spdx

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/quay/claircore"

	"github.com/spdx/tools-golang/tagvalue"
)

func TestParseIndexReport(t *testing.T) {
	//ctx := context.Background()
	for _, ir := range testIndexReports {
		t.Run("TODO", func(t *testing.T) {

			s, err := ParseIndexReport(ir)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Packages) != 2 {
				t.Error("expecting 2 packages")
			}
			w := &bytes.Buffer{}
			err = tagvalue.Write(s, w)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(string(w.Bytes()))

		})
	}
	t.Error()
}

var testIndexReports = []*claircore.IndexReport{
	{
		Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
		Packages: map[string]*claircore.Package{
			"123": {
				ID:      "123",
				Name:    "package A",
				Version: "v1.0.0",
			},
			"456": {
				ID:      "456",
				Name:    "package B",
				Version: "v2.0.0",
			},
		},
		Environments: map[string][]*claircore.Environment{
			"123": {
				{
					PackageDB:     "var/lib/dpkg/status",
					IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
					RepositoryIDs: []string{"11"},
				},
			},
			"456": {
				{
					PackageDB:     "maven:opt/couchbase/lib/cbas/repo/eventstream-1.0.1.jar",
					IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
					RepositoryIDs: []string{"12"},
				},
			},
		},
	},
}
