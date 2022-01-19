package libindex_test

import (
	"context"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
)

func ExampleLibindex() {
	ctx := context.TODO()
	opts := &libindex.Opts{
		Migrations: true,
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
