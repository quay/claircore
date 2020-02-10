package pep440

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type versionTestcase struct {
	Name string
	In   string
	Err  bool
	Want Version
}

func (tc versionTestcase) Run(t *testing.T) {
	t.Logf("%s → %s", tc.In, tc.Want.String())
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
			In:   "1.0.0",
			Err:  false,
			Want: Version{Release: []int{1, 0, 0}},
		},
		{
			Name: "All",
			In:   "1!2.3.4-a5-post_6.dev7.8",
			Err:  false,
			Want: Version{
				Epoch:   1,
				Release: []int{2, 3, 4},
				Pre: struct {
					Label string
					N     int
				}{
					Label: "a",
					N:     5,
				},
				Post: 6,
				Dev:  7,
			},
		},
		{
			Name: "Date",
			In:   "2019.3",
			Err:  false,
			Want: Version{Release: []int{2019, 3}},
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
		t.Logf("%s → %s → %v", in, v.String(), v.Version())
	}

	sort.Sort(Versions(vs))

	got := make([]string, len(tc.In))
	for i, v := range vs {
		got[i] = v.String()
	}
	if !cmp.Equal(tc.Want, got) {
		t.Fatal(cmp.Diff(tc.Want, got))
	}
	t.Log("\n" + strings.Join(got, "\n"))
}

func TestOrdering(t *testing.T) {
	// These are taken from examples in PEP-440.
	tt := []orderTestcase{
		{
			Name: "AllSuffixes",
			Want: []string{
				"1.0.dev456",
				"1.0a1",
				"1.0a2.dev456",
				"1.0a12.dev456",
				"1.0a12",
				"1.0b1.dev456",
				"1.0b2",
				"1.0b2.post345.dev456",
				"1.0b2.post345",
				"1.0rc1.dev456",
				"1.0rc1",
				"1.0",
				"1.0.post456.dev34",
				"1.0.post456",
				"1.1.dev1",
			},
			In: []string{
				"1.0",
				"1.0.dev456",
				"1.0.post456",
				"1.0.post456.dev34",
				"1.0a1",
				"1.0a12",
				"1.0a12.dev456",
				"1.0a2.dev456",
				"1.0b1.dev456",
				"1.0b2",
				"1.0b2.post345",
				"1.0b2.post345.dev456",
				"1.0rc1",
				"1.0rc1.dev456",
				"1.1.dev1",
			},
		},
		{
			Name: "MajorMinor",
			In:   []string{"1.1", "1.0", "0.3", "0.2", "0.1"},
			Want: []string{"0.1", "0.2", "0.3", "1.0", "1.1"},
		},
		{
			Name: "MajorMinorMicro",
			In:   []string{"1.2.0", "1.1.0", "1.1.2", "1.1.1"},
			Want: []string{"1.1.0", "1.1.1", "1.1.2", "1.2.0"},
		},
		{
			Name: "MajorMinorPre",
			In:   []string{"0.9", "1.0", "1.0a", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.1a1"},
			Want: []string{"0.9", "1.0a0", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.1a1"},
		},
		{
			Name: "MajorMinorPreDevPost",
			In:   []string{"0.9", "1.0", "1.0.dev1", "1.0.dev2", "1.0.dev3", "1.0.dev4", "1.0.post1", "1.0c1", "1.0c2", "1.1.dev1"},
			Want: []string{"0.9", "1.0.dev1", "1.0.dev2", "1.0.dev3", "1.0.dev4", "1.0rc1", "1.0rc2", "1.0", "1.0.post1", "1.1.dev1"},
		},
		{
			Name: "Date",
			In:   []string{"2013.2", "2013.1", "2012.3", "2012.2", "2012.15", "2012.1"},
			Want: []string{"2012.1", "2012.2", "2012.3", "2012.15", "2013.1", "2013.2"},
		},
		{
			Name: "Epoch",
			In:   []string{"1!1.0", "1!1.1", "1!2.0", "2013.10", "2014.04"},
			Want: []string{"2013.10", "2014.4", "1!1.0", "1!1.1", "1!2.0"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
