package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// LayerFetchOpt tells libindex where to store fetched layers
type LayerFetchOpt string

const (
	// OnDisk - layers will be fetched via HTTP and writen to disk. When scanned the contents will be read from a fd.
	OnDisk LayerFetchOpt = "ondisk"
	// InMem - layers will be fetched via HTTP and writen to the layer's in memory byte array. When scanned the contents will be read from this in memory byte array
	InMem LayerFetchOpt = "inmem"
	// Tee - layers will be fetched via HTTP and written both the layer's in memory byte array and onto disk.
	Tee LayerFetchOpt = "tee"
)

// Realizer is responsible for downloading a layer, uncompressing
// if necessary, and making the uncompressed tar contents available for
// reading.
type Realizer interface {
	Realize(context.Context, []*claircore.Layer) error
	Close() error
}
