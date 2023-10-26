package ruby

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewVersion(t *testing.T) {
	testcases := []struct {
		version string
		valid   bool
	}{
		{
			version: "1",
			valid:   true,
		},
		{
			version: "1.",
			valid:   false,
		},
		{
			version: "1.alpha",
			valid:   true,
		},
		{
			version: "1-alpha",
			valid:   true,
		},
		{
			version: "",
			valid:   true,
		},
		{
			version: ".3",
			valid:   false,
		},
		{
			version: "beta",
			valid:   false,
		},
		{
			version: "beta.1",
			valid:   false,
		},
		{
			version: "-",
			valid:   false,
		},
		{
			version: "0-0",
			valid:   true,
		},
		{
			version: "1/2",
			valid:   false,
		},
		{
			version: "1..2",
			valid:   false,
		},
		{
			version: "1111111111111111111111111111111111111111111111111111111",
			valid:   true,
		},
		{
			version: "1.234567890987654321234567890987654321234567890987654321234567890987654.3.21",
			valid:   true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.version, func(t *testing.T) {
			_, err := NewVersion(tc.version)
			if !cmp.Equal(tc.valid, err == nil) {
				t.Error(cmp.Diff(tc.valid, err == nil))
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	testcases := []struct {
		a, b string
		want int
	}{
		{
			a:    "1",
			b:    "2",
			want: -1,
		},
		{
			a:    "1.1.2",
			b:    "1.1.0",
			want: +1,
		},
		{
			a:    "1.1.02",
			b:    "1.1.0",
			want: +1,
		},
		{
			a:    "1.1.2",
			b:    "1.1.2",
			want: 0,
		},
		{
			a:    "5",
			b:    "4.2.10",
			want: +1,
		},
		{
			a:    "4.2.10",
			b:    "5",
			want: -1,
		},
		{
			a:    "4.2.10",
			b:    "4.2.10.0.0.0.0.0.0",
			want: 0,
		},
		{
			a:    "0.9",
			b:    "1.0",
			want: -1,
		},
		{
			a:    "0.9",
			b:    "1.0.a.2",
			want: -1,
		},
		{
			a:    "1.0.a.2",
			b:    "1.0.b1",
			want: -1,
		},
		{
			a:    "1.0.b1",
			b:    "1.0",
			want: -1,
		},
		{
			a:    "0.alpha",
			b:    "0",
			want: -1,
		},
		{
			a:    "1-2",
			b:    "1-2",
			want: 0,
		},
		{
			a:    "1-1",
			b:    "1-2",
			want: -1,
		},
		{
			a:    "1-2",
			b:    "1-1",
			want: +1,
		},
		{
			a:    "1.2.3.0.00.0-0.0.0000.3.0000.00000000",
			b:    "1.2.3.0.0.0-0.0.0.3.0.0",
			want: 0,
		},
		{
			a:    "1.2.3.0.00.0-0.0.000000000000000000000000000000000000000000000000000000000000000000.3.0000.00000000",
			b:    "1.2.3.0.0.0-0.0.0.3.0.0",
			want: 0,
		},
		{
			a:    "1.2.3.0.00.0-0.0.0000.3.0000.00000000",
			b:    "1.2.3.0.0.0-0.0.0.3",
			want: 0,
		},
		{
			a:    "1.2.3.0.00.0-0.0.0000.3.0000.00000000",
			b:    "1.2.3-0.0.0.3",
			want: 0,
		},
		{
			a:    "1.0.3.beta",
			b:    "1.beta",
			want: +1,
		},
		{
			a:    "1.0.3.00.0.0.4.0.0.0.0.beta.0.0.2.0.0.00000",
			b:    "1.0.3.00.0.0.4.beta.0.0.2",
			want: 0,
		},
		{
			a:    "1.0.3.00.0.0.4.0.0.0.0.beta.0.0.2.0.0.00000",
			b:    "1.0.3.00.0.0.4.alpha.0.0.2",
			want: +1,
		},
		{
			a:    "   1.alpha.0.1.0.5.00000.0",
			b:    " 1.alpha.0.1.0.5.0          ",
			want: 0,
		},
		{
			a:    "",
			b:    "\t",
			want: 0,
		},
		{
			a:    "1.2.000000000000000000000000000000000000000000000000000000000001",
			b:    "1.2.1",
			want: 0,
		},
		{
			a:    "1.2.000000000000000000000000000000000000000000000000000000000001",
			b:    "1.2.2",
			want: -1,
		},
		{
			a:    "1.234567890987654321234567890987654321234567890987654321234567890987654.3.21",
			b:    "1.000000000000000000234567890987654321234567890987654321234567890987654.3.21",
			want: +1,
		},
		{
			a:    "9999999999999999999999999999999999999999999999999999999999999999999999999999",
			b:    "00000000009999999999999999999999999999999999999999999999999999999999999999999999999999",
			want: 0,
		},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%s_%s", tc.a, tc.b), func(t *testing.T) {
			aVersion, err := NewVersion(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			bVersion, err := NewVersion(tc.b)
			if err != nil {
				t.Fatal(err)
			}

			got := aVersion.Compare(bVersion)
			if !cmp.Equal(tc.want, got) {
				t.Error(cmp.Diff(tc.want, got))
			}
		})
	}
}
