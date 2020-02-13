package claircore

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type versionTestcase struct {
	Name    string
	Version Version
	Want    string
}

func (tc versionTestcase) StringTest(t *testing.T) {
	t.Logf("%v → %s", tc.Version, tc.Want)
	if got := tc.Version.String(); !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}

func (tc versionTestcase) MarshalTest(t *testing.T) {
	var got Version
	t.Logf("%v", tc.Version)

	b, err := tc.Version.MarshalText()
	if err != nil {
		t.Error(err)
	}
	t.Logf("%v → %q", tc.Version, string(b))
	if err := got.UnmarshalText(b); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(tc.Version, got) {
		t.Error(cmp.Diff(tc.Version, got))
	}
}

var versiontt = []versionTestcase{
	{
		Name: "Zero",
		Version: Version{
			Kind: "test",
			V:    [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		Want: "0",
	},
	{
		Name: "Simple",
		Version: Version{
			Kind: "test",
			V:    [...]int32{0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		Want: "1",
	},
	{
		Name: "Epoch",
		Version: Version{
			Kind: "test",
			V:    [...]int32{1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		Want: "1!1",
	},
	{
		Name: "ZeroEpoch",
		Version: Version{
			Kind: "test",
			V:    [...]int32{1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		Want: "1!0",
	},
	{
		Name: "Range",
		Version: Version{
			Kind: "test",
			V:    [...]int32{1, 1, 0, 0, 0, 1, 0, 0, 0, 0},
		},
		Want: "1!1.0.0.0.1",
	},
	{
		Name: "MidRange",
		Version: Version{
			Kind: "test",
			V:    [...]int32{1, 0, 0, 1, 0, 1, 0, 0, 0, 0},
		},
		Want: "1!1.0.1",
	},
}

func TestVersionString(t *testing.T) {
	for _, tc := range versiontt {
		t.Run(tc.Name, tc.StringTest)
	}
}

func TestVersionMarshal(t *testing.T) {
	for _, tc := range versiontt {
		t.Run(tc.Name, tc.MarshalTest)
	}
}
