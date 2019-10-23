package scanner

import (
	"context"

	"github.com/quay/claircore"
)

// Coalescer takes a set of layers and creates coalesced ScanReport.
//
// A coalesced ScanReport should provide only the packages present in the
// final container image once all layers were applied.
type Coalescer interface {
	Coalesce(ctx context.Context, layers []*claircore.Layer) (*claircore.ScanReport, error)
}
