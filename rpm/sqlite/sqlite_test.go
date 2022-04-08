package sqlite

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestPackages(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	db, err := Open(`testdata/rpmdb.sqlite`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	var want []Info
	f, err := os.Open(`testdata/rpmdb.sqlite.want`)
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

	got, err := db.Packages(ctx)
	if err != nil {
		t.Error(err)
	}

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
