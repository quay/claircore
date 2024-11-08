package docs

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
)

func Example_libvuln() {
	ctx := context.TODO()

	// ANCHOR: new
	opts := new(libvuln.Options)
	// Populate with desired settings...
	lib, err := libvuln.New(ctx, opts)
	if err != nil {
		panic(err)
	}
	defer lib.Close(ctx)
	// ANCHOR_END: new

	liopts := new(libindex.Options)
	// Populate with desired settings...
	indexer, err := libindex.New(ctx, liopts, http.DefaultClient)
	if err != nil {
		panic(err)
	}
	defer indexer.Close(ctx)
	// ANCHOR: scan
	m := new(claircore.Manifest)
	// Populate somehow ...
	ir, err := indexer.Index(ctx, m)
	if err != nil {
		panic(err)
	}
	vr, err := lib.Scan(ctx, ir)
	if err != nil {
		panic(err)
	}
	// ANCHOR_END: scan
	_ = vr

	// ANCHOR: ops
	ops, err := lib.UpdateOperations(ctx, `updater`)
	if err != nil {
		panic(err)
	}
	// ANCHOR_END: ops
	// ANCHOR: ops_print
	for updater, ops := range ops {
		fmt.Printf("ops for updater %s, %+v", updater, ops)
	}
	// ANCHOR_END: ops_print
	// ANCHOR: ops_diff
	for upd, ops := range ops {
		fmt.Printf("updater: %v", upd)
		diff, err := lib.UpdateDiff(ctx, ops[1].Ref, ops[0].Ref)
		if err != nil {
			panic(err)
		}
		for _, vuln := range diff.Added {
			fmt.Printf("vuln %+v added in %v", vuln, diff.Cur.Ref)
		}
	}
	// ANCHOR_END: ops_diff
}
