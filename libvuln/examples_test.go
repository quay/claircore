package libvuln_test

import (
	"context"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
)

func ExampleLibvuln() {
	ctx := context.TODO()
	opts := &libvuln.Opts{
		Migrations: true,
		// see definition for more configuration option
	}
	lib, err := libvuln.New(ctx, opts)
	if err != nil {
		panic(err)
	}

	for range time.Tick(5 * time.Second) {
		ok, err := lib.Initialized(ctx)
		if err != nil {
			panic(err)
		}
		if ok {
			break
		}
	}

	ir := &claircore.IndexReport{}
	vr, err := lib.Scan(ctx, ir)
	if err != nil {
		panic(err)
	}
	_ = vr
}
