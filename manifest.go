package claircore

// Manifest represents a docker image. Layers array MUST be indexed
// in the order that image layers are stacked.
type Manifest struct {
	// content addressable hash. should be able to be computed via
	// the hashes of all included layers
	Hash Digest `json:"hash"`
	// an array of filesystem layers indexed in the same order as the cooresponding image
	Layers []*Layer `json:"layers"`
}
