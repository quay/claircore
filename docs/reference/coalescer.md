# Coalescer
A coalescer must compute the final contents of a manifest given the artifacts found at each layer.

```go
package indexer

// layerArifact aggregates the any artifacts found within a layer
type LayerArtifacts struct {
	Hash  claircore.Digest
	Pkgs  []*claircore.Package
	Dist  []*claircore.Distribution // each layer can only have a single distribution
	Repos []*claircore.Repository
}

// Coalescer takes a set of layers and creates coalesced IndexReport.
//
// A coalesced IndexReport should provide only the packages present in the
// final container image once all layers were applied.
type Coalescer interface {
	Coalesce(ctx context.Context, artifacts []*LayerArtifacts) (*claircore.IndexReport, error)
}

```

A Coalsecer implementation is free to determine this computation given the artifacts found in a layer. 
A Coalescer is called with a slice of LayerArtifacts structs. The manifest's layer ordering is preserved in the provided slice.
