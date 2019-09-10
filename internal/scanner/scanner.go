package scanner

import (
	"context"

	"github.com/quay/claircore"
)

// Scanner is an interface for taking a manifest and creating
// a ScanReport inventorying the necessary data from the manifest's
// layers
type Scanner interface {
	// Scan should block and provide a ScanReport inventoring items of
	// interest in each layer
	Scan(ctx context.Context, manifest *claircore.Manifest) *claircore.ScanReport
	// Lock should ensure no other distributed process can scan
	// the provided manifest.
	Lock(ctx context.Context, hash string) error
	// Unlock should free a lock acquired by Lock() and allow
	// other distributed processes to make progress
	Unlock() error
}
