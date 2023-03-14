package pep440

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type rangeTestcase struct {
	Name  string
	In    string
	Want  Range
	Match []matchTestcase
}

type matchTestcase struct {
	In    string
	Match bool
}

func (tc rangeTestcase) RunParse(t *testing.T) {
	t.Logf("%s → %s", tc.In, tc.Want.String())
	r, err := ParseRange(tc.In)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(tc.Want, r) {
		t.Error(cmp.Diff(tc.Want, r))
	}
}

func (tc rangeTestcase) RunMatch(t *testing.T) {
	t.Log(tc.In)
	r, err := ParseRange(tc.In)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Match) == 0 {
		t.SkipNow()
	}
	for _, pair := range tc.Match {
		t.Run(pair.In, func(t *testing.T) {
			v, err := Parse(pair.In)
			if err != nil {
				t.Fatal(err)
			}
			got, want := r.Match(&v), pair.Match
			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
	if !cmp.Equal(tc.Want, r) {
		t.Error(cmp.Diff(tc.Want, r))
	}
}

var rangeCases = []rangeTestcase{
	{
		Name: "Simple",
		In:   ">1.0",
		Want: Range{
			criterion{Op: opGT, V: Version{Release: []int{1, 0}}},
		},
		Match: []matchTestcase{
			{In: "1.0", Match: false},
			{In: "1.0.0.pre1", Match: false},
			{In: "1.0.0.1", Match: true},
			{In: "2.0", Match: true},
		},
	},
	{
		Name: "SimpleLT",
		In:   "<2022.12.07",
		Want: Range{
			criterion{Op: opLT, V: Version{Release: []int{2022, 12, 7}}},
		},
		Match: []matchTestcase{
			{In: "2022.12.07", Match: false},
			{In: "2022.12.7", Match: false},
			{In: "2022.12.08", Match: false},
			{In: "2022.12.06", Match: true},
		},
	},
	{
		Name: "SimpleLTE",
		In:   "<=2022.12.07",
		Want: Range{
			criterion{Op: opLTE, V: Version{Release: []int{2022, 12, 7}}},
		},
		Match: []matchTestcase{
			{In: "2022.12.07", Match: true},
			{In: "2022.12.7", Match: true},
			{In: "2022.12.08", Match: false},
			{In: "2022.12.8", Match: false},
		},
	},
	{
		Name: "Compatible",
		In:   "~=1.1",
		Want: Range{
			criterion{Op: opGTE, V: Version{Release: []int{1, 1}}},
			criterion{Op: opLT, V: Version{Release: []int{2}}},
		},
		Match: []matchTestcase{
			{In: "1.1", Match: true},
			{In: "1.1.0.pre1", Match: false},
			{In: "1.1.0.1", Match: true},
			{In: "2.0", Match: false},
		},
	},
	{
		Name: "CompatiblePatch",
		In:   "~=1.1.10",
		Want: Range{
			criterion{Op: opGTE, V: Version{Release: []int{1, 1, 10}}},
			criterion{Op: opLT, V: Version{Release: []int{1, 2}}},
		},
		Match: []matchTestcase{
			{In: "1.1", Match: false},
			{In: "1.1.10.pre1", Match: false},
			{In: "1.1.10.1", Match: true},
			{In: "2.0", Match: false},
		},
	},
	{
		Name: "CompatiblePost",
		In:   "~= 2.2.post3",
		Want: Range{
			criterion{Op: opGTE, V: Version{Release: []int{2, 2}, Post: 3}},
			criterion{Op: opLT, V: Version{Release: []int{3}}},
		},
		Match: []matchTestcase{
			{In: "2.2", Match: false},
			{In: "2.2.0.pre1", Match: false},
			{In: "2.2.0.1", Match: true},
			{In: "3.0", Match: false},
		},
	},
	{
		Name: "CompatibleSpecific",
		In:   "~= 2.2.0",
		Want: Range{
			criterion{Op: opGTE, V: Version{Release: []int{2, 2, 0}}},
			criterion{Op: opLT, V: Version{Release: []int{2, 3}}},
		},
		Match: []matchTestcase{
			{In: "2.2", Match: true},
			{In: "2.2.0.pre1", Match: false},
			{In: "2.2.0.1", Match: true},
			{In: "3.0", Match: false},
		},
	},
	{
		Name: "CompatibleSpecificLong",
		In:   "~= 1.4.5.0",
		Want: Range{
			criterion{Op: opGTE, V: Version{Release: []int{1, 4, 5, 0}}},
			criterion{Op: opLT, V: Version{Release: []int{1, 4, 6}}},
		},
		Match: []matchTestcase{
			{In: "1.4.4", Match: false},
			{In: "1.4.5.0.pre1", Match: false},
			{In: "1.4.5.0.1", Match: true},
			{In: "2.0", Match: false},
			{In: "1.4", Match: false},
			{In: "1.4.0.0.0.0", Match: false},
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
		Match: []matchTestcase{
			{In: "1.1", Match: true},
			{In: "1.1.0.pre1", Match: false},
			{In: "1.1.0.1", Match: true},
			{In: "2.0", Match: false},
			{In: "1.4", Match: false},
			{In: "1.4.0.0.0.0", Match: false},
		},
	},
}

func TestRange(t *testing.T) {
	for _, tc := range rangeCases {
		t.Run(tc.Name, tc.RunParse)
	}
}

func TestMatch(t *testing.T) {
	for _, tc := range rangeCases {
		t.Run(tc.Name, tc.RunMatch)
	}
}
