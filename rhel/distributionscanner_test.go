package rhel

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

func TestDistributionScanner(t *testing.T) {
	t.Parallel()
	sys := os.DirFS(`testdata/releasefiles`)
	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Run(e.Name(), func(t *testing.T) {
			n := path.Base(t.Name())
			sys, err := fs.Sub(sys, n)
			if err != nil {
				t.Fatal(err)
			}
			d, err := findDistribution(context.Background(), sys)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasPrefix(n, "oracle-"):
				if d != nil {
					t.Fatalf("incorrect distribution: %s:%s", d.DID, d.VersionID)
				}
			case n == "hummingbird":
				if d == nil {
					t.Fatal("missing distribution")
				}
				if got, want := d.DID, "hummingbird"; got != want {
					t.Errorf("DID: got %q, want %q", got, want)
				}
				if got, want := d.VersionID, "20251124"; got != want {
					t.Errorf("VersionID: got %q, want %q", got, want)
				}
				if got, want := d.Name, "Hummingbird OS"; got != want {
					t.Errorf("Name: got %q, want %q", got, want)
				}
			default:
				if d == nil {
					t.Fatal("missing distribution")
				}
				if got, want := d.Version, strings.TrimPrefix(n, "atomichost-"); got != want {
					t.Errorf("got: %q, want %q", got, want)
				}
			}
		})
	}
}
