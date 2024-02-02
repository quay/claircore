package vex

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"
)

func TestEscapeCPE(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "wildcard version",
			in:   "cpe:/a:redhat:openshift:4.*",
			want: "cpe:/a:redhat:openshift:4.%02",
		},
		{
			name: "product with a wildcard",
			in:   "cpe:/a:redhat:astarry.*.comp:4.*",
			want: "cpe:/a:redhat:astarry.*.comp:4.%02",
		},
		{
			name: "version with question",
			in:   "cpe:/a:redhat:openshift:4.?::el8",
			want: "cpe:/a:redhat:openshift:4.%01::el8",
		},
		{
			name: "question mark can be anywhere",
			in:   "cpe:/a:redhat:openshift:4.?.10::el8",
			want: "cpe:/a:redhat:openshift:4.%01.10::el8",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			out := escapeCPE(tc.in)
			if out != tc.want {
				t.Errorf("expected %s but got %s", tc.want, out)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	c := context.Background()
	url, err := url.Parse(BaseURL)
	if err != nil {
		t.Error(err)
	}

	testcases := []struct {
		name            string
		filename        string
		expectedVulns   int
		expectedDeleted int
	}{
		{
			name:            "six_advisories_two_deletions",
			filename:        "testdata/example_vex.jsonl",
			expectedVulns:   546,
			expectedDeleted: 2,
		},
		{
			name:            "cve-2022-1705",
			filename:        "testdata/cve-2022-1705.jsonl",
			expectedVulns:   736,
			expectedDeleted: 0,
		},
	}

	u := &Updater{url: url, client: http.DefaultClient}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.filename)
			if err != nil {
				t.Fatalf("failed to open test data file %s: %v", tc.filename, err)
			}

			// Ideally, you'd just use snappy.Encode() but apparently
			// the stream format and the block format are not interchangeable:
			// https://pkg.go.dev/github.com/klauspost/compress/snappy#Writer.
			b, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read file bytes: %v", err)
			}
			var buf bytes.Buffer
			sw := snappy.NewBufferedWriter(&buf)
			bLen, err := sw.Write(b)
			if err != nil {
				t.Fatalf("error writing snappy data to buffer: %v", err)
			}
			if bLen != len(b) {
				t.Errorf("didn't write the correct # of bytes")
			}
			if err = sw.Close(); err != nil {
				t.Errorf("failed to close snappy Writer: %v", err)
			}

			vulns, deleted, err := u.DeltaParse(c, io.NopCloser(&buf))
			if err != nil {
				t.Fatalf("failed to parse CSAF JSON: %v", err)
			}
			if len(vulns) != tc.expectedVulns {
				t.Fatalf("expected %d vulns but got %d", tc.expectedVulns, len(vulns))
			}
			if len(deleted) != tc.expectedDeleted {
				t.Fatalf("expected %d deleted but got %d", tc.expectedDeleted, len(deleted))
			}
		})
	}
}
