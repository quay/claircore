package ovalutil

import "testing"

func TestValidVersion(t *testing.T) {
	tt := []struct {
		Match bool
		In    string
	}{
		{
			Match: false,
			In:    "5.7 only",
		},
		{
			Match: false,
			In:    "extremely\nbroken",
		},
		{
			Match: true,
			In:    "10.3+deb10u12",
		},
	}
	for _, tc := range tt {
		ok := validVersion.MatchString(tc.In)
		t.Logf("%#q:\tgot: %v, want: %v", tc.In, ok, tc.Match)
		if tc.Match != ok {
			t.Error()
		}
	}
}
