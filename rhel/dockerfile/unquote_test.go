package dockerfile

import (
	"errors"
	"testing"

	"golang.org/x/text/transform"
)

func TestUnquote(t *testing.T) {
	u := NewUnquote()

	t.Run("Fragment", func(t *testing.T) {
		s := "🚮"
		_, _, err := transform.String(u, s[:len(s)-1])
		if got, want := err, transform.ErrShortSrc; !errors.Is(got, want) {
			t.Fatalf("bad error: got: %v, want: %v", got, want)
		}
	})

	t.Run("ShortDst", func(t *testing.T) {
		src := []byte("input")
		for i := range src {
			dst := make([]byte, i)
			u.Reset()
			_, _, err := u.Transform(dst, src, true)
			if got, want := err, transform.ErrShortDst; !errors.Is(got, want) {
				t.Logf("dst size: %d", len(dst))
				t.Fatalf("bad error: got: %v, want: %v", got, want)
			}
		}
	})

	tcs := []struct {
		In   string
		Want string
	}{
		{"", ""},
		{"bareword", "bareword"},
		{`'single \''`, `single '`},
		{`"single '"`, `single '`},
		{`"double \""`, `double "`},
		{`"double \""`, `double "`},
		{`"double	"`, "double\t"},
	}

	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			got, n, err := transform.String(u, tc.In)
			t.Logf("got: %#q, want: %#q", got, tc.Want)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if n != len(tc.In) {
				t.Errorf("consumed %d/%d", n, len(tc.In))
			}
			if got != tc.Want {
				t.Fail()
			}
		})
	}
}
