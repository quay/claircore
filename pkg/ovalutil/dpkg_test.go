package ovalutil

import "testing"

func TestResolveVersionCodeName(t *testing.T) {
	table := []struct {
		ver    string
		expect string
	}{
		{
			ver:    "1:8.2p1-4ubuntu0.2",
			expect: "1:8.2p1-4ubuntu0.2",
		},
		{
			ver:    "0:0",
			expect: "0:0",
		},
		{
			ver:    "0:1:3.0.1",
			expect: "1:3.0.1",
		},
		{
			ver:    "0:1:3.3p1-0.0woody1",
			expect: "1:3.3p1-0.0woody1",
		},
		{
			ver:    "0:1:3.8.1p1-8.sarge.4",
			expect: "1:3.8.1p1-8.sarge.4",
		},
		{
			ver:    "0:1:3.8.1p1-4",
			expect: "1:3.8.1p1-4",
		},
		{
			ver:    "1:3.4",
			expect: "1:3.4",
		},
		{
			ver:    "0:1:3.6.1p2-6.0",
			expect: "1:3.6.1p2-6.0",
		},
	}

	for _, tt := range table {
		out := correctDoubleEpoch(tt.ver)
		if got, want := out, tt.expect; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
	}
}
