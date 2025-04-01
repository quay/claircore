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

	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/sqlite"
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

				want := loadWant(t, ar)
				nat := openNativeDB(t, filename)

				blobs, dbErr := nat.All(ctx)
				infos, parseErr := parseBlob(ctx, blobs)
				defer func() {
					if err := errors.Join(dbErr(), parseErr()); err != nil {
						t.Error(err)
					}
				}()
				got := make(map[string][]string, len(want))
				for info := range infos {
					got[info.Name] = info.Filenames
				}

				if !cmp.Equal(got, want) {
					t.Error(cmp.Diff(got, want))
				}
			})
		}
	})
}

func loadWant(t testing.TB, ar *txtar.Archive) map[string][]string {
	for _, f := range ar.Files {
		if f.Name == "want.json" {
			want := make(map[string][]string)
			if err := json.Unmarshal(f.Data, &want); err != nil {
				t.Fatal(err)
			}
			return want
		}
	}
	t.Fatal(`"want.json" not found`)
	panic("unreachable")
}

func openNativeDB(t testing.TB, filename string) NativeDB {
	t.Helper()

	pre, _, ok := strings.Cut(filename, `/testdata/`)
	if !ok {
		t.Fatal("input file not in a testdata directory")
	}

	var err error
	var f *os.File
	switch pre {
	case `bdb`, `ndb`:
		f, err = os.Open(filename)
		if err != nil {
			t.Fatal(err)
		} else {
			t.Cleanup(func() { f.Close() })
		}
	case `sqlite`:
		f, err = os.Create(filepath.Join(t.TempDir(), "db"))
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
	default:
		panic("programmer error")
	}

	var inner innerDB
	switch pre {
	case `bdb`:
		var db bdb.PackageDB
		if err := db.Parse(f); err != nil {
			t.Fatal(err)
		}
		inner = &db
	case `ndb`:
		var db ndb.PackageDB
		if err := db.Parse(f); err != nil {
			t.Fatal(err)
		}
		inner = &db
	case `sqlite`:
		filename = f.Name()
		t.Logf("copied sqlite database to: %s", filename)

		db, err := sqlite.Open(filename)
		if err != nil {
			t.Fatal(err)
		}
		inner = db
	}

	nat := &nativeAdapter{innerDB: inner}
	t.Cleanup(func() {
		if err := nat.Close(); err != nil {
			t.Error(err)
		}
	})
	return nat
}
