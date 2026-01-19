package wasm

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGuessCacheDir(t *testing.T) {
	t.Run("Precise", func(t *testing.T) {
		t.Setenv("CACHE_DIRECTORY", strings.Join([]string{
			"/var/tmp",
			"/run/clair",
			"/run/claircore/matcher_wasm",
		}, ":"))

		want := "/run/claircore/matcher_wasm"
		got := guessCachedir()
		t.Logf("got: %q, want: %q", got, want)
		if got != want {
			t.Error(cmp.Diff(got, want))
		}
	})
	t.Run("GuessWithEnv", func(t *testing.T) {
		t.Setenv("CACHE_DIRECTORY", strings.Join([]string{
			"/var/tmp",
			"/run/clair",
		}, ":"))

		want := "/var/tmp/matcher_wasm"
		got := guessCachedir()
		t.Logf("got: %q, want: %q", got, want)
		if got != want {
			t.Error(cmp.Diff(got, want))
		}
	})
	t.Run("Guess", func(t *testing.T) {
		t.Setenv("XDG_CACHE_HOME", "/cachedir")

		want := "/cachedir/claircore/matcher_wasm"
		got := guessCachedir()
		t.Logf("got: %q, want: %q", got, want)
		if got != want {
			t.Error(cmp.Diff(got, want))
		}
	})
}
