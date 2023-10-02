package aws

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/aws/internal/alas"
)

func TestVersionString(t *testing.T) {
	testcases := []struct {
		pkg      alas.Package
		expected string
	}{
		{
			pkg: alas.Package{
				Epoch:   "",
				Version: "3.3.10",
				Release: "26.amzn2",
			},
			expected: "3.3.10-26.amzn2",
		},
		{
			pkg: alas.Package{
				Epoch:   "0",
				Version: "3.3.10",
				Release: "26.amzn2",
			},
			expected: "3.3.10-26.amzn2",
		},
		{
			pkg: alas.Package{
				Epoch:   "10",
				Version: "3.1.0",
				Release: "8.amzn2.0.8",
			},
			expected: "10:3.1.0-8.amzn2.0.8",
		},
	}

	var b strings.Builder
	for _, testcase := range testcases {
		v := versionString(&b, testcase.pkg)
		if !cmp.Equal(v, testcase.expected) {
			t.Errorf(cmp.Diff(v, testcase.expected))
		}
	}
}
