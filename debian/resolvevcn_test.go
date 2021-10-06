package debian

import (
	"testing"
)

func TestResolveVersionCodeName(t *testing.T) {
	table := []struct {
		str    string
		expect string
	}{
		{
			str:    "Debian GNU/Linux 11 (bullseye)",
			expect: "bullseye",
		},
		{
			str:    "11 (bullseye)",
			expect: "bullseye",
		},
		{
			str:    "Debian GNU/Linux 10 (buster)",
			expect: "buster",
		},
		{
			str:    "10 (buster)",
			expect: "buster",
		},
		{
			str:    "Debian GNU/Linux 8 (jessie)",
			expect: "jessie",
		},
		{
			str:    "8 (jessie)",
			expect: "jessie",
		},
		{
			str:    "Debian GNU/Linux 9 (stretch)",
			expect: "stretch",
		},
		{
			str:    "9 (stretch)",
			expect: "stretch",
		},
		{
			str:    "Debian GNU/Linux 7 (wheezy)",
			expect: "wheezy",
		},
		{
			str:    "7 (wheezy)",
			expect: "wheezy",
		},
		{
			str:    "Debian GNU/Linux 10",
			expect: "",
		},
		{
			str:    "10",
			expect: "",
		},
		{
			str:    "Debian GNU/Linux 8",
			expect: "",
		},
		{
			str:    "8",
			expect: "",
		},
		{
			str:    "Debian GNU/Linux 9",
			expect: "",
		},
		{
			str:    "9",
			expect: "",
		},
		{
			str:    "Debian GNU/Linux 7",
			expect: "",
		},
		{
			str:    "7",
			expect: "",
		},
	}

	for _, tt := range table {
		out := ResolveVersionCodeName(map[string]string{
			"test": tt.str,
		})
		if got, want := out, tt.expect; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
	}
}
