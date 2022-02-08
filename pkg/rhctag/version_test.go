package rhctag

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type versionTestcase struct {
	Name string
	In   string
	Want Version
	Err  bool
}

func (tc versionTestcase) Run(t *testing.T) {
	t.Logf("%s → %s", tc.In, tc.Want.Original)
	v, err := Parse(tc.In)
	if (err != nil) != tc.Err {
		t.Error(err)
	}
	if !cmp.Equal(tc.Want, v) {
		t.Error(cmp.Diff(tc.Want, v))
	}
}

func TestSimple(t *testing.T) {
	tt := []versionTestcase{
		{
			Name: "Simple",
			In:   "v1.0.0",
			Err:  false,
			Want: Version{
				Major:    1,
				Minor:    0,
				Original: "v1.0.0",
			},
		},
		{
			Name: "Patch",
			In:   "v1.0.1",
			Err:  false,
			Want: Version{
				Major:    1,
				Minor:    0,
				Original: "v1.0.1",
			},
		},
		{
			Name: "Date",
			In:   "v1.0.0-202201121008",
			Err:  false,
			Want: Version{
				Major:    1,
				Minor:    0,
				Original: "v1.0.0-202201121008",
			},
		},
		{
			Name: "Prerelease",
			In:   "v1.0.0-1",
			Err:  false,
			Want: Version{
				Major:    1,
				Minor:    0,
				Original: "v1.0.0-1",
			},
		},
		{
			Name: "Prerelease",
			In:   "v4.6.0-202112140546.p0.g8b9da97.assembly.stream",
			Err:  false,
			Want: Version{
				Major:    4,
				Minor:    6,
				Original: "v4.6.0-202112140546.p0.g8b9da97.assembly.stream",
			},
		},
		{
			Name: "Prerelease-gittag",
			In:   "v4.8.0-202107291502.p0.git.0519730.assembly.stream",
			Err:  false,
			Want: Version{
				Major:    4,
				Minor:    8,
				Original: "v4.8.0-202107291502.p0.git.0519730.assembly.stream",
			},
		},
		{
			Name: "ubi-toolbox",
			In:   "8.5-21.1645811927",
			Err:  false,
			Want: Version{
				Major:    8,
				Minor:    5,
				Original: "8.5-21.1645811927",
			},
		},
		{
			Name: "ocs4/mcg-core-rhel8",
			In:   "5.8.0-38.e060925.5.8",
			Err:  false,
			Want: Version{
				Major:    5,
				Minor:    8,
				Original: "5.8.0-38.e060925.5.8",
			},
		},
		{
			Name: "rhceph/rhceph-4-dashboard-rhel8",
			In:   "4-22",
			Err:  false,
			Want: Version{
				Major:    4,
				Minor:    0,
				Original: "4-22",
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

type orderTestcase struct {
	Name string
	In   []string
	Want []string
}

func (tc orderTestcase) Run(t *testing.T) {
	vs := make([]Version, len(tc.In))
	for i, in := range tc.In {
		v, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
		t.Logf("%s → %s", in, v.Original)
	}

	sort.Sort(Versions(vs))

	got := make([]string, len(tc.In))
	for i, v := range vs {
		got[i] = v.Original
	}
	if !cmp.Equal(tc.Want, got) {
		t.Fatal(cmp.Diff(tc.Want, got))
	}
	t.Log("\n" + strings.Join(got, "\n"))
}

func TestOrdering(t *testing.T) {
	tt := []orderTestcase{
		{
			Name: "Datetime",
			In:   []string{"v1.0.1-1", "v1.0.1-202201121008", "v1.0.1"},
			Want: []string{"v1.0.1", "v1.0.1-1", "v1.0.1-202201121008"},
		},
		{
			Name: "Datetime-full",
			In:   []string{"v1.0.1-1", "v1.0.1-202201121008.blah.foo.bar", "v1.0.1"},
			Want: []string{"v1.0.1", "v1.0.1-1", "v1.0.1-202201121008.blah.foo.bar"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
