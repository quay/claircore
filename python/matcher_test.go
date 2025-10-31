package python_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/test"
)

type matcherTestcase struct {
	Matcher driver.Matcher
	Name    string
	R       claircore.IndexRecord
	V       claircore.Vulnerability
	Want    bool
}

func (tc matcherTestcase) Run(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
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
	t.Parallel()
	testcases := []matcherTestcase{
		{
			Name: "Simple",
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
			Name: "BoundedHit",
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
			Name: "BoundedMiss",
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
			Name: "Test0",
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
			Name: "Test1",
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
			Name: "Test2",
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
		{
			Name: "Test3",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "0.5+local.1",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg3",
				},
				FixedInVersion: "fixed=1.0+local.2&introduced=0.8",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
		{
			Name: "Test4",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0.0",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg4",
				},
				FixedInVersion: "introduced=2.2.0&lastAffected=3.0.1",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
		{
			Name: "Test5",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "3.0.1",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg5",
				},
				FixedInVersion: "introduced=2.2.0&lastAffected=3.0.1",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "Test6",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "3.0.2",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg6",
				},
				FixedInVersion: "introduced=2.2.0&lastAffected=3.0.1",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
		{
			Name: "Test7",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "3.0.2",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg7",
				},
				FixedInVersion: "introduced=2.2.0",
			},
			Want:    true,
			Matcher: &python.Matcher{},
		},
		{
			Name: "Test8",
			R: claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "3.0.2",
				},
			},
			V: claircore.Vulnerability{
				Package: &claircore.Package{
					Name: "testPkg8",
				},
				FixedInVersion: "introduced=3.2.0",
			},
			Want:    false,
			Matcher: &python.Matcher{},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.Name, func(t *testing.T) {
			ctx := test.Logging(t)
			got, err := testcase.Matcher.Vulnerable(ctx, &testcase.R, &testcase.V)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.Want) {
				t.Error(cmp.Diff(got, testcase.Want))
			}
		})
	}

	ctx := test.Logging(t)
	test.RunMatcherTests(ctx, t, "testdata/matcher", new(python.Matcher))
}
