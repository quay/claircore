# Coalescer
A coalescer must compute the final contents of a manifest given the artifacts
found at each layer.

{{# godoc internal/indexer.Coalescer}}
{{# godoc internal/indexer.LayerArtifacts}}

A `Coalsecer` implementation is free to determine this computation given the
artifacts found in a layer. A `Coalescer` is called with a slice of
`LayerArtifacts` structs. The manifest's layer ordering is preserved in the
provided slice.
