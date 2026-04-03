package types

import "bytes"

// PackageKind indicates what kind of package is being described.
type PackageKind uint

const (
	// "Unknown" is the default value.
	UnknownPackage PackageKind = iota // unknown
	// A "source" package is software that must be compiled or otherwise
	// processed before it's ready to use.
	//
	// Conceptually, all "binary" packages come from a "source" package. A
	// single "source" package produces one or more other packages.
	//
	// It can be used to describe the set of packages produced from the source
	// package.
	SourcePackage // source
	// A "binary" package is compiled or otherwise ready-to-use software.
	//
	// It describes a set of files inside a container image.
	BinaryPackage // binary
	// A "layer" package is used to refer to a container layer itself.
	//
	// Conceptually, a "layer" package is a higher type that describes the
	// container image rather than the contents.
	LayerPackage // layer
	// An "ancestry" package is used to refer to a container layer and all
	// previous layers in an image.
	//
	// Conceptually, an "ancestry" package is a higher type that describes the
	// container image rather than the contents.
	AncestryPackage // ancestry
)

func (k PackageKind) MarshalText() (text []byte, err error) {
	return []byte(k.String()), nil
}

func (k *PackageKind) UnmarshalText(text []byte) error {
	i := bytes.Index([]byte(_PackageKind_name), text)
	if i == -1 {
		*k = PackageKind(0)
		return nil
	}
	idx := uint8(i)
	for i, off := range _PackageKind_index {
		if off == idx {
			*k = PackageKind(i)
			return nil
		}
	}
	panic("unreachable")
}
