package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// Resolver is used for any reasoning that needs to be done with all the layers in context.
//
// Resolvers are called at the end of the coalesce step when reports
// from separate scanners are merged.
type Resolver interface {
	Resolve(context.Context, *claircore.IndexReport, []*claircore.Layer) *claircore.IndexReport
}
