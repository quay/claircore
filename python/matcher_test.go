package python_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
)

type matcherTestcase struct {
	Matcher driver.Matcher
	Name    string
	R       claircore.IndexRecord
	V       claircore.Vulnerability
	Want    bool
}

func (tc matcherTestcase) Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = zlog.Test(ctx, t)
	got, err := tc.Matcher.Vulnerable(ctx, &tc.R, &tc.V)
	if err != nil {
		t.Error(err)
	}
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
	testcases := []matcherTestcase{
		{
			Name: "simple",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "0.9.8",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "test2",
				},
				FixedInVersion: "fixed=1.0.0&introduced=0.7.0",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "bounded/hit",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.4.3",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "test3",
				},
				FixedInVersion: "fixed=1.4.4&introduced=0",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "bounded/miss",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.4.3",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "test4",
				},
				FixedInVersion: "fixed=1.4.3&introduced=0",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
		{
			Name: "test0",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0a1",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg0",
				},
				FixedInVersion: "fixed=1.0b1&introduced=0",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "test1",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0.post1",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg1",
				},
				FixedInVersion: "fixed=1.0.post2&introduced=0",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "test2",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0+local.1",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg2",
				},
				FixedInVersion: "fixed=1.0+local.2&introduced=0",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.Name, func(t *testing.T) {
			got, err := testcase.Matcher.Vulnerable(context.Background(), &testcase.R, &testcase.V)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.Want) {
				t.Error(cmp.Diff(got, testcase.Want))
			}
		})
	}
}
