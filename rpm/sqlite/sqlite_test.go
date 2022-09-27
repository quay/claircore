package sqlite

import (
	"context"
	"encoding/json"
	"hash/crc64"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestPackages(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	h := crc64.New(crc64.MakeTable(crc64.ISO))

	db, err := Open(`testdata/rpmdb.sqlite`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
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

	hdrs, err := db.AllHeaders(ctx)
	if err != nil {
		t.Error(err)
	}
	var got []uint64
	for _, rd := range hdrs {
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
