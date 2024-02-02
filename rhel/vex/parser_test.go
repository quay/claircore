package vex

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
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
				t.Fatalf("failed to open test data: %v", tc.filename)
			}
			vulns, _, err := u.DeltaParse(c, f)
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
