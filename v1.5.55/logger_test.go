package docs_test

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/quay/claircore/toolkit/log"
)

// Example_logger is an example annotated for inclusion in the prose
// documentation.
func Example_logger() {
	ctx := context.Background()
	{
		// ANCHOR: kvs
		log := slog.With("contextual", "value")
		log.DebugContext(ctx, "message")
		// ANCHOR_END: kvs
	}

	{
		// ANCHOR: ctx
		ctx := log.With(ctx, "contextual", "value")
		slog.DebugContext(ctx, "message")
		// ANCHOR_END: ctx
	}

	// ANCHOR: bad_example
	slog.InfoContext(ctx, fmt.Sprintf("done at: %v", time.Now()))
	// ANCHOR_END: bad_example
	// ANCHOR: good_example
	slog.InfoContext(ctx, "done", "time", time.Now())
	// ANCHOR_END: good_example
}
