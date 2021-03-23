package ovalutil

import (
	"testing"

	"github.com/quay/goval-parser/oval"
)

type definitionTypeTestCase struct {
	def        oval.Definition
	want, name string
	err        bool
}

func TestGetDefinitionType(t *testing.T) {
	testCases := []definitionTypeTestCase{
		{
			def:  oval.Definition{ID: "oval:com.redhat.cve:def:20162166"},
			want: CVEDefinition,
			err:  false,
			name: "CVE",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.unaffected:def:202014340"},
			want: UnaffectedDefinition,
			err:  false,
			name: "unaffected",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhsa:def:20190966"},
			want: RHSADefinition,
			err:  false,
			name: "RHSA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhba:def:20193384"},
			want: RHBADefinition,
			err:  false,
			name: "RHBA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhea:def:20193845"},
			want: RHEADefinition,
			err:  false,
			name: "RHEA",
		},
		{
			def:  oval.Definition{ID: "oval:com.redhat.rhea::20193845"},
			want: "",
			err:  true,
			name: "malformed definition",
		},
		{
			def:  oval.Definition{ID: ""},
			want: "",
			err:  true,
			name: "empty ID",
		},
	}

	for _, tc := range testCases {
		got, err := GetDefinitionType(tc.def)
		if !tc.err && err != nil {
			t.Errorf("%q returned error while it shouldn't", tc.name)
		}
		if tc.err && err == nil {
			t.Errorf("%q didn't return error while it should", tc.name)
		}
		if tc.want != got {
			t.Errorf("%q failed: want %q, got %q", tc.name, tc.want, got)
		}
	}
}
