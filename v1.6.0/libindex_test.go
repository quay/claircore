package docs

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
)

func Example_libindex() {
	ctx := context.TODO()

	// ANCHOR: new
	opts := new(libindex.Options)
	// Populate with desired settings...
	lib, err := libindex.New(ctx, opts, http.DefaultClient)
	if err != nil {
		panic(err)
	}
	defer lib.Close(ctx) // Remember to cleanup when done.
	// ANCHOR_END: new

	// ANCHOR: index
	m := new(claircore.Manifest)
	// Populate somehow ...
	ir, err := lib.Index(ctx, m)
	if err != nil {
		panic(err)
	}
	// ANCHOR_END: index
	_ = ir

	// ANCHOR: indexreport
	ir, ok, err := lib.IndexReport(ctx, m.Hash)
	if err != nil {
		panic(err)
	}
	// ANCHOR_END: indexreport
	_ = ok

	var prevState string
	// ANCHOR: state
	state, err := lib.State(ctx)
	if err != nil {
		panic(err)
	}
	if state == prevState {
		// Nothing to do.
		return
	}
	// Otherwise, re-index manifest.
	// ANCHOR_END: state

	// ANCHOR: affectedmanifests
	var vulns []claircore.Vulnerability
	affected, err := lib.AffectedManifests(ctx, vulns)
	if err != nil {
		panic(err)
	}
	for manifest, vulns := range affected.VulnerableManifests {
		for _, vuln := range vulns {
			fmt.Printf("vuln affecting manifest %s: %+v", manifest, vuln)
		}
	}
	// ANCHOR_END: affectedmanifests
}
