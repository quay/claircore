package vex

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"
)

func TestParse(t *testing.T) {
	c := context.Background()
	url, err := url.Parse(baseURL)
	if err != nil {
		t.Error(err)
	}

	testcases := []struct {
		name     string
		filename string
		expected int
	}{
		{
			name:     "six_advisories",
			filename: "testdata/example_vex.jsonl",
			expected: 546,
		},
	}

	u := &VEXUpdater{url: url, client: http.DefaultClient}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.filename)
			if err != nil {
				t.Fatalf("failed to open test data file %s: %v", tc.filename, err)
			}

			// Ideally, you'd just use snappy.Encode() but apparently
			// the stream format and the block format are not interchangable:
			// https://pkg.go.dev/github.com/klauspost/compress/snappy#Writer.
			b, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read file bytes: %v", err)
			}
			var buf bytes.Buffer
			sw := snappy.NewBufferedWriter(&buf)
			defer sw.Close()
			bLen, err := sw.Write(b)
			if err != nil {
				t.Fatalf("error writing snappy data to buffer: %v", err)
			}
			if bLen != len(b) {
				t.Errorf("didn't write the correct # of bytes")
			}

			vulns, _, err := u.DeltaParse(c, io.NopCloser(&buf))
			if err != nil {
				t.Fatalf("failed to parse CSAF JSON: %v", err)
			}
			for _, v := range vulns {
				fmt.Println(v.Name)
				fmt.Println(v.Package.Name)
				fmt.Println(v.Repo.Name)
			}

			if len(vulns) != tc.expected {
				t.Fatalf("expected %d vulns but got %d", tc.expected, len(vulns))
			}

		})
	}
}
