package docs_test

import (
	"context"
	"time"

	"github.com/quay/zlog"
)

// Example_logger is an example annotated for inclusion in the prose
// documentation.
func Example_logger() {
	ctx := context.Background()
	// ANCHOR: kvs
	ctx = zlog.ContextWithValues(ctx,
		"component", "Example.Logger")
	// ANCHOR_END: kvs

	// ANCHOR: bad_example
	zlog.Info(ctx).Msgf("done at: %v", time.Now())
	// ANCHOR_END: bad_example
	// ANCHOR: good_example
	zlog.Info(ctx).
		Time("time", time.Now()).
		Msgf("done")
	// ANCHOR_END: good_example
}
