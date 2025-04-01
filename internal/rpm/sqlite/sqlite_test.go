package sqlite

import (
	"context"
	"encoding/json"
	"hash/crc64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestPackages(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	db := openDB(t, `testdata/rpmdb.sqlite`)
	if err := db.Validate(ctx); err != nil {
		t.Error("error validating sqlite DB", err)
	}

	var want []uint64
	f, err := os.Open(`testdata/rpmdb.sqlite.checksums`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := json.NewDecoder(f).Decode(&want); err != nil {
		t.Error(err)
	}

	blobs, check := db.All(ctx)
	defer func() {
		if err := check(); err != nil {
			t.Error(err)
		}
	}()
	h := crc64.New(crc64.MakeTable(crc64.ISO))
	var got []uint64
	for rd := range blobs {
		h.Reset()
		if _, err := io.Copy(h, rd.(io.Reader)); err != nil {
			t.Error(err)
			continue
		}
		got = append(got, h.Sum64())
	}

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

func TestValidate(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	db := openDB(t, `testdata/no_packages.sqlite`)
	if err := db.Validate(ctx); err == nil {
		t.Error("expecting error from Validate() for empty DB")
	}
}

func openDB(t testing.TB, srcname string) *RPMDB {
	t.Helper()

	// Copying to a tempdir is needed if the tests are being run from a prepared
	// module. In that case, the module's layout is read-only and attempting any
	// queries tries to create wal files alongside the database file.
	dbfile := filepath.Join(t.TempDir(), `rpmdb.sqlite`)

	dst, err := os.Create(dbfile)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	src, err := os.Open(srcname)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Sync(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dbfile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})

	return db
}
