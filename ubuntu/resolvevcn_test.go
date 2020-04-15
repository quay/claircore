package ubuntu

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
			str:    "19.04 (Disco Dingo)",
			expect: "disco",
		},
		{
			str:    "18.10 (Cosmic Cuttlefish)",
			expect: "cosmic",
		},
		{
			str:    "18.04.3 LTS (Bionic Beaver)",
			expect: "bionic",
		},
		{
			str:    "16.04.6 LTS (Xenial Xerus)",
			expect: "xenial",
		},
		{
			str:    "14.04.6 LTS, Trusty Tahr",
			expect: "trusty",
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
			str:    "19.04",
			expect: "",
		},
		{
			str:    "18.10",
			expect: "",
		},
		{
			str:    "18.04.3 LTS",
			expect: "",
		},
		{
			str:    "17.10",
			expect: "",
		},
		{
			str:    "16.04.6 LTS",
			expect: "",
		},
		{
			str:    "14.04.6 LTS",
			expect: "",
		},
		{
			str:    "12.04.5 LTS",
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
