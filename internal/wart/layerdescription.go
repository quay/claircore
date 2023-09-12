package wart

import (
	"github.com/quay/claircore"
)

// BUG(hank) There's currently extra copies between [claircore.Layer] and
// [claircore.LayerDescription] because of the original sin of making the
// internal layer object also the external layer description. In the future, the
// external API should not accept [claircore.Layer] and instead deal in
// [claircore.LayerDescription].

// LayersToDescriptions takes a slice of [claircore.Layer] pointers and creates
// equivalent [claircore.LayerDescription]s.
//
// This is a helper for shims from a previous API that takes a [claircore.Layer]
// pointer slice to a new one that takes a [claircore.LayerDescription] slice.
//
// If the previous API is expected to mutate the [claircore.Layer] pointers,
// make sure to call [CopyLayerPointers] to ensure the correct values end up in
// the original slice.
func LayersToDescriptions(ls []*claircore.Layer) (ds []claircore.LayerDescription) {
	ds = make([]claircore.LayerDescription, len(ls))
	for i, l := range ls {
		d := &ds[i]
		d.MediaType = `application/vnd.oci.image.layer.v1.tar`
		d.Digest = l.Hash.String()
		d.URI = l.URI
		d.Headers = make(map[string][]string, len(l.Headers))
		for k, v := range l.Headers {
			c := make([]string, len(v))
			copy(c, v)
			d.Headers[k] = c
		}
	}
	return ds
}

// DescriptionsToLayers takes a slice of [claircore.LayerDescription]s and
// creates equivalent [claircore.Layer] pointers.
//
// This is a helper for shims from a new API that takes a
// [claircore.LayerDescription] slice to a previous API that takes a
// [claircore.Layer] pointer slice.
func DescriptionsToLayers(ds []claircore.LayerDescription) []*claircore.Layer {
	// Set up return slice.
	ls := make([]claircore.Layer, len(ds))
	ret := make([]*claircore.Layer, len(ds))
	for i := range ls {
		ret[i] = &ls[i]
	}
	// Populate the Layers.
	for i := range ds {
		d, l := &ds[i], ret[i]
		l.Hash = claircore.MustParseDigest(d.Digest)
		l.URI = d.URI
		l.Headers = make(map[string][]string, len(d.Headers))
		for k, v := range d.Headers {
			c := make([]string, len(v))
			copy(c, v)
			l.Headers[k] = c
		}
	}
	return ret
}

// CopyLayerPointers ensures that "dst" ends up with pointers to the equivalent
// [claircore.Layer]s (as determined by [claircore.Layer.Hash] equality) in
// "src".
//
// This function is O(n²), so if one can prove that "src" is unmodified without
// walking both slices, the call to this function should be omitted.
//
// Needing to use this indicates the API that's being shimmed has subtle state
// assumptions and should really be redesigned.
func CopyLayerPointers[L LayerOrPointer](dst []*claircore.Layer, src []L) {
	if len(src) == 0 {
		return
	}
	var z L
	for i := range src {
		for j, a := range dst {
			var b *claircore.Layer
			switch any(z).(type) {
			case claircore.Layer:
				b = any(&src[i]).(*claircore.Layer)
			case *claircore.Layer:
				b = any(src[i]).(*claircore.Layer)
			default:
				panic("unreachable")
			}
			if a.Hash.String() == b.Hash.String() {
				dst[j] = b
			}
		}
	}
}

// LayerOrPointer abstracts over a [claircore.Layer] or a pointer to a
// [claircore.Layer]. A user of this type will still need to do runtime
// reflection due to the lack of sum types.
type LayerOrPointer interface {
	claircore.Layer | *claircore.Layer
}
