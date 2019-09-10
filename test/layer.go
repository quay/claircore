package test

import (
	"fmt"

	"github.com/quay/claircore"
)

// GenUniqueLayers generates n unique layers and populates RemotePath.URI with the provided
// URIs. it is an error for n != len(URIs)
func GenUniqueLayersRemote(n int, URIs []string) ([]*claircore.Layer, error) {
	if n != len(URIs) {
		return nil, fmt.Errorf("lenght of URIs array must equal the number of layers being generated")
	}
	layers := []*claircore.Layer{}
	for i := 0; i < n; i++ {
		layers = append(layers, &claircore.Layer{
			Hash:        fmt.Sprintf("test-layer-%d", i),
			Format:      fmt.Sprintf("test-format"),
			ImageFormat: fmt.Sprintf("test-image-format"),
			RemotePath: claircore.RemotePath{
				URI: URIs[i],
			},
		})
	}
	return layers, nil
}
