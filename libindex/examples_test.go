package libindex_test

import (
	"context"
	"net/http"
	"os"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/pkg/ctxlock/v2"
)

func ExampleLibindex() {
	ctx := context.TODO()
	pool, err := postgres.Connect(ctx, "connection string", "libindex-test")
	if err != nil {
		panic(err)
	}

	store, err := postgres.InitPostgresIndexerStore(ctx, pool, true)
	if err != nil {
		panic(err)
	}

	ctxLocker, err := ctxlock.New(ctx, pool)
	if err != nil {
		panic(err)
	}

	opts := &libindex.Options{
		Store:      store,
		Locker:     ctxLocker,
		FetchArena: libindex.NewRemoteFetchArena(http.DefaultClient, os.TempDir()),
		// see definition for more configuration options
	}
	lib, err := libindex.New(ctx, opts, http.DefaultClient)
	if err != nil {
		panic(err)
	}
	m := &claircore.Manifest{}

	ir, err := lib.Index(ctx, m)
	if err != nil {
		panic(err)
	}
	if ir.State == "IndexError" {
		panic(ir.Err)
	}
}
