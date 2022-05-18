package linux

import (
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// DistSearcher uses ClairCore's heuristic to determine a distribution for
// a given layer.
//
// The searcher will first see if distribution information exists for the queried layer.
// Next the searcher will look backwards in the layer history for distribution information.
// Finally the searcher will look forward in the layer history as a final effort to find distribution info.
type DistSearcher struct {
	dists []*claircore.Distribution
}

func NewDistSearcher(artifacts []*indexer.LayerArtifacts) DistSearcher {
	dists := make([]*claircore.Distribution, len(artifacts))

	// record where dists show up in layers via slice
	for i, artifact := range artifacts {
		if len(artifact.Dist) > 0 {
			dists[i] = artifact.Dist[0] // we dont support multiple dists found in a layer
		}
	}
	return DistSearcher{dists}
}

func (ds DistSearcher) Search(n int) (*claircore.Distribution, error) {
	if n >= len(ds.dists) || n < 0 {
		return nil, fmt.Errorf("provided manifest contains %d layers. %d is out of bounds", len(ds.dists), n)
	}

	if found := ds.dists[n]; found != nil {
		return found, nil
	}

	// first search backwards
	for i := n - 1; i >= 0; i-- {
		if ds.dists[i] != nil {
			return ds.dists[i], nil
		}
	}

	// now search forward
	for i := n + 1; i < len(ds.dists); i++ {
		if ds.dists[i] != nil {
			return ds.dists[i], nil
		}
	}
	return nil, nil
}

func (ds DistSearcher) Dists() []*claircore.Distribution {
	out := make([]*claircore.Distribution, 0)
	for _, dist := range ds.dists {
		if dist != nil {
			out = append(out, dist)
		}
	}
	return out
}
