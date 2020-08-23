package docs_test

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// Example_logger is an example annotated for inclusion in the prose
// documentation.
func Example_logger() {
	ctx := context.Background()
	// ANCHOR: logger
	log := zerolog.Ctx(ctx).With().
		// ANCHOR_END: logger
		// ANCHOR: kvs
		Str("component", "Example.Logger").
		// ANCHOR_END: kvs
		// ANCHOR: newlogger
		Logger()
		// ANCHOR_END: newlogger
	// ANCHOR: context
	ctx = log.WithContext(ctx)
	// ANCHOR_END: context

	// ANCHOR: bad_example
	log.Info().Msgf("done at: %v", time.Now())
	// ANCHOR_END: bad_example
	// ANCHOR: good_example
	log.Info().
		Time("time", time.Now()).
		Msgf("done")
	// ANCHOR_END: good_example
}
