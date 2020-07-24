package python_test

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
)

type matcherTestcase struct {
	Name    string
	R       claircore.IndexRecord
	V       claircore.Vulnerability
	Want    bool
	Matcher driver.Matcher
}

func (tc matcherTestcase) Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, _ := tc.Matcher.Vulnerable(ctx, &tc.R, &tc.V)
	want := tc.Want
	if got != want {
		t.Errorf("got: %v, want: %v", got, want)
		t.Logf("record:\n%#+v", &tc.R)
		t.Logf("package:\n%#+v\n%#+v", tc.R.Package, tc.R.Package.NormalizedVersion)
		t.Logf("vulnerability:\n%#+v", &tc.V)
		t.Logf("range:\n%#+v", tc.V.Range)
	}
}

// TestMatcher tests the python matcher.
func TestMatcher(t *testing.T) {
	tt := []matcherTestcase{
		{
			Name: "simple",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "0.9.8",
					NormalizedVersion: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 0, 9, 8, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			V: claircore.Vulnerability{
				Range: &claircore.Range{
					Lower: claircore.Version{Kind: "pep440"},
					Upper: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "bounded/hit",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.4.3",
					NormalizedVersion: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 4, 3, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			V: claircore.Vulnerability{
				Range: &claircore.Range{
					Lower: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
					},
					Upper: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 5, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "bounded/miss",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.4.3",
					NormalizedVersion: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 4, 3, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			V: claircore.Vulnerability{
				Range: &claircore.Range{
					Lower: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
					},
					Upper: claircore.Version{
						Kind: "pep440",
						V:    [...]int32{0, 1, 4, 3, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			Matcher: &python.Matcher{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
