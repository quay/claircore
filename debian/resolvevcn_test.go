package debian

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ResolveVersionCodeName_Found(t *testing.T) {
	table := []struct {
		str    string
		expect string
	}{
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
	}

	for _, tt := range table {
		out := ResolveVersionCodeName(map[string]string{
			"test": tt.str,
		})
		assert.Equal(t, tt.expect, out)
	}
}

func Test_ResolveVersionCodeName_NotFound(t *testing.T) {
	table := []struct {
		str    string
		expect string
	}{
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
		assert.Equal(t, tt.expect, out)
	}
}
