package pep440

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type rangeTestcase struct {
	Name string
	In   string
	Want Range
}

func (tc rangeTestcase) Run(t *testing.T) {
	t.Logf("%s → %s", tc.In, tc.Want.String())
	r, err := ParseRange(tc.In)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(tc.Want, r) {
		t.Error(cmp.Diff(tc.Want, r))
	}
}

func TestRange(t *testing.T) {
	tt := []rangeTestcase{
		{
			Name: "Simple",
			In:   ">1.0",
			Want: Range{
				criterion{Op: opGT, V: Version{Release: []int{1, 0}}},
			},
		},
		{
			Name: "Compatible",
			In:   "~=1.1",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{1, 1}}},
				criterion{Op: opLT, V: Version{Release: []int{2}}},
			},
		},
		{
			Name: "CompatiblePatch",
			In:   "~=1.1.10",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{1, 1, 10}}},
				criterion{Op: opLT, V: Version{Release: []int{1, 2}}},
			},
		},
		{
			Name: "CompatiblePost",
			In:   "~= 2.2.post3",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{2, 2}, Post: 3}},
				criterion{Op: opLT, V: Version{Release: []int{3}}},
			},
		},
		{
			Name: "CompatibleSpecific",
			In:   "~= 2.2.0",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{2, 2, 0}}},
				criterion{Op: opLT, V: Version{Release: []int{2, 3}}},
			},
		},
		{
			Name: "CompatibleSpecific",
			In:   "~= 1.4.5.0",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{1, 4, 5, 0}}},
				criterion{Op: opLT, V: Version{Release: []int{1, 4, 6}}},
			},
		},
		{
			Name: "Weird",
			In:   "~=1.1, !=1.4",
			Want: Range{
				criterion{Op: opGTE, V: Version{Release: []int{1, 1}}},
				criterion{Op: opLT, V: Version{Release: []int{2}}},
				criterion{Op: opExclusion, V: Version{Release: []int{1, 4}}},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
