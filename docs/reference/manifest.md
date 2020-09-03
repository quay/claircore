# Manifest
A Manifest is analogous to an [OCI Image Manifest](https://github.com/opencontainers/image-spec/blob/master/manifest.md): it defines the order of layers and how to retrieve the them.

```go
// Manifest represents a docker image. Layers array MUST be indexed
// in the order that image layers are stacked.
type Manifest struct {
	// content addressable hash. should be able to be computed via
	// the hashes of all included layers
	Hash Digest `json:"hash"`
	// an array of filesystem layers indexed in the same order as the cooresponding image
	Layers []*Layer `json:"layers"`
}
```
