package spdx

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"

	"github.com/spdx/tools-golang/tagvalue"
)

func TestIndexReportsRoundTrip(t *testing.T) {
	opts := cmp.Options{
		cmp.AllowUnexported(claircore.IndexReport{}),
		cmpopts.IgnoreFields(claircore.IndexReport{}, "Hash"),
		cmpopts.IgnoreFields(claircore.Environment{}, "IntroducedIn"),
	}

	ms, err := filepath.Glob("testdata/indexreport*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range ms {
		name := filepath.Base(n)
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			b, _ := ioutil.ReadAll(f)
			ir1 := &claircore.IndexReport{}
			if err := json.Unmarshal(b, ir1); err != nil {
				t.Fatal(err)
			}
			s, err := ParseIndexReport(ir1)
			if err != nil {
				t.Fatal(err)
			}
			w := &bytes.Buffer{}
			err = tagvalue.Write(s, w)
			if err != nil {
				t.Fatal(err)
			}
			sReport, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(sReport))
			ir2, err := ParseSPDXDocument(s)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(ir1, ir2, opts) {
				t.Error(cmp.Diff(ir2, ir1, opts))
			}
			// iReport, err := json.MarshalIndent(ir2, "", "  ")
			// if err != nil {
			// 	t.Fatal(err)
			// }
			//t.Log(string(iReport))
		})
	}

}

func TestParseRoundTrip(t *testing.T) {
	opts := cmp.Options{
		cmp.AllowUnexported(claircore.IndexReport{}),
		cmpopts.IgnoreFields(claircore.IndexReport{}, "Hash"),
		cmpopts.IgnoreFields(claircore.Environment{}, "IntroducedIn"),
	}
	for _, tt := range testIndexReports {
		t.Run(tt.name, func(t *testing.T) {

			s, err := ParseIndexReport(tt.indexReport)
			if err != nil {
				t.Fatal(err)
			}
			w := &bytes.Buffer{}
			err = tagvalue.Write(s, w)
			if err != nil {
				t.Fatal(err)
			}
			sReport, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(sReport))
			ir, err := ParseSPDXDocument(s)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(ir, tt.indexReport, opts) {
				t.Error(cmp.Diff(tt.indexReport, ir, opts))
			}
			iReport, err := json.MarshalIndent(ir, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(iReport))

		})
	}
}

type testcase struct {
	name        string
	indexReport *claircore.IndexReport
}

var testIndexReports = []testcase{
	{
		name: "simple index report",
		indexReport: &claircore.IndexReport{
			Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
			Packages: map[string]*claircore.Package{
				"123": {
					ID:      "123",
					Name:    "package A",
					Version: "v1.0.0",
					Source: &claircore.Package{
						ID:      "122",
						Name:    "package B source",
						Kind:    claircore.SOURCE,
						Version: "v1.0.0",
					},
					Kind: claircore.BINARY,
				},
				"456": {
					ID:      "456",
					Name:    "package B",
					Version: "v2.0.0",
					Kind:    claircore.BINARY,
				},
			},
			Environments: map[string][]*claircore.Environment{
				"123": {
					{
						PackageDB:      "bdb:var/lib/rpm",
						IntroducedIn:   claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
						RepositoryIDs:  []string{"11"},
						DistributionID: "13",
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
			Repositories: map[string]*claircore.Repository{
				"11": {
					ID:   "11",
					Name: "cpe:/a:redhat:rhel_eus:8.6::appstream",
					Key:  "rhel-cpe-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:rhel_eus:8.6:*:appstream:*:*:*:*:*"),
				},
				"12": {
					ID:   "12",
					Name: "maven",
					URI:  "https://repo1.maven.apache.org/maven2",
				},
			},
			Distributions: map[string]*claircore.Distribution{
				"13": {
					ID:         "13",
					DID:        "rhel",
					Name:       "Red Hat Enterprise Linux Server",
					Version:    "7",
					VersionID:  "7",
					CPE:        cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"),
					PrettyName: "Red Hat Enterprise Linux Server 7",
				},
			},
			Success: true,
		},
	},
}
