package ovalutil

import (
	"testing"

	"github.com/quay/goval-parser/oval"
)

// TestArchMatch tests oval architecture match
func TestArchMatch(t *testing.T) {
	t.Parallel()

	type testcase struct {
		Name         string
		PkgArch      string
		RequiredArch string
		Operation    oval.Operation
		Want         bool
	}
	testcases := []testcase{
		{
			Name:         "equal-match",
			PkgArch:      "x86_64",
			RequiredArch: "x86_64",
			Operation:    oval.OpEquals,
			Want:         true,
		},
		{
			Name:         "equal-not-match",
			PkgArch:      "x86_64",
			RequiredArch: "ppc64le",
			Operation:    oval.OpEquals,
			Want:         false,
		},
		{
			Name:         "pattern-match",
			PkgArch:      "x86_64",
			RequiredArch: "x86_64|ppc64le",
			Operation:    oval.OpPatternMatch,
			Want:         true,
		},
		{
			Name:         "pattern-not-match",
			PkgArch:      "x86_64",
			RequiredArch: "s390x|ppc64le",
			Operation:    oval.OpPatternMatch,
			Want:         false,
		},
		{
			Name:         "no-vuln-arch",
			PkgArch:      "noarch",
			RequiredArch: "",
			Operation:    oval.OpEquals,
			Want:         true,
		},
		{
			Name:         "no-pkg-arch",
			PkgArch:      "",
			RequiredArch: "x86_64",
			Operation:    oval.OpEquals,
			Want:         false,
		},
	}

	for _, testCase := range testcases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				got := ArchMatch(
					testCase.PkgArch,
					testCase.RequiredArch,
					testCase.Operation,
				)
				if got != testCase.Want {
					t.Errorf("got: %v, want: %v", got, testCase.Want)
				}
			},
		)
	}

}
