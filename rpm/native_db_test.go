package rpm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/rpm/bdb"
	"github.com/quay/claircore/rpm/internal/rpm"
	"github.com/quay/claircore/rpm/ndb"
	"github.com/quay/claircore/rpm/sqlite"
)

func TestInfo(t *testing.T) {
	t.Run("Files", func(t *testing.T) {
		ms, err := filepath.Glob("testdata/Info.Files.*.txtar")
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.TrimPrefix(strings.TrimSuffix(filepath.Base(m), ".txtar"), "Info.Files.")
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ctx := zlog.Test(context.Background(), t)
				filename := strings.TrimSpace(string(ar.Comment))
				t.Logf("opening %q", filename)

				var want map[string][]string
				for _, f := range ar.Files {
					if f.Name == "want.json" {
						want = make(map[string][]string)
						if err := json.Unmarshal(f.Data, &want); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
				if want == nil {
					t.Fatal(`"want.json" not found`)
				}

				pre, _, ok := strings.Cut(filename, `/testdata/`)
				if !ok {
					t.Fatal("input file not in a testdata directory")
				}

				var nat nativeDB
				switch pre {
				case `bdb`:
					f, err := os.Open(filename)
					if err != nil {
						t.Fatal(err)
					} else {
						t.Cleanup(func() { f.Close() })
					}
					var db bdb.PackageDB
					if err := db.Parse(f); err != nil {
						t.Fatal(err)
					}
					nat = &db
				case `ndb`:
					f, err := os.Open(filename)
					if err != nil {
						t.Fatal(err)
					} else {
						t.Cleanup(func() { f.Close() })
					}
					var db ndb.PackageDB
					if err := db.Parse(f); err != nil {
						t.Fatal(err)
					}
					nat = &db
				case `sqlite`:
					f, err := os.Create(filepath.Join(t.TempDir(), "db"))
					if err != nil {
						t.Fatal(err)
					}
					src, err := os.Open(filename)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := io.Copy(f, src); err != nil {
						t.Fatal(err)
					}
					if err := errors.Join(src.Close(), f.Close()); err != nil {
						t.Fatal(err)
					}
					filename = f.Name()
					t.Logf("copied sqlite database to: %s", filename)

					db, err := sqlite.Open(filename)
					if err != nil {
						t.Fatal(err)
					} else {
						t.Cleanup(func() { db.Close() })
					}
					nat = db
				}

				rds, err := nat.AllHeaders(ctx)
				if err != nil {
					t.Fatal(err)
				}

				got := make(map[string][]string, len(want))
				for _, rd := range rds {
					var h rpm.Header
					if err := h.Parse(ctx, rd); err != nil {
						t.Error(err)
						continue
					}
					var info Info
					if err := info.Load(ctx, &h); err != nil {
						t.Error(err)
						continue
					}
					if info.Name == "gpg-pubkey" {
						// This is *not* an rpm package. It is just a public key stored in the rpm database.
						// Ignore this "package".
						continue
					}
					got[info.Name] = info.Filenames
				}

				if !cmp.Equal(got, want) {
					t.Error(cmp.Diff(got, want))
				}
			})
		}
	})
}
