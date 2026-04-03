package claircore

import (
	"bytes"
	"slices"

	"github.com/quay/claircore/pkg/cpe"
)

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind PackageKind `json:"kind,omitempty"`
	// if type is a binary package a source package maybe present which built this binary package.
	// must be a pointer to support recursive type:
	Source *Package `json:"source,omitempty"`
	// the file system path or prefix where this package resides
	PackageDB string `json:"-"`
	// a location in the layer where the package is located, this is useful for language packages.
	Filepath string `json:"-"`
	// a hint on which repository this package was downloaded from
	RepositoryHint string `json:"-"`
	// NormalizedVersion is a representation of a version string that's
	// correctly ordered when compared with other representations from the same
	// producer.
	NormalizedVersion Version `json:"normalized_version"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
	// CPE name for package
	CPE cpe.WFN `json:"cpe"`
	// Detector that discovered this package
	Detector *Detector `json:"detector"`
}

// PackageKind indicates what kind of package is being described.
type PackageKind uint

func (k PackageKind) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k *PackageKind) UnmarshalText(text []byte) error {
	pos := bytes.Index([]byte(_PackageKind_name), text)
	x := slices.Index(_PackageKind_index[1:], uint8(pos))
	x++
	*k = PackageKind(x)
	return nil
}

const (
	// "Unknown" is the default value which string-ifies to an empty string, the
	// way the previous string-based representation did.
	packageUnknown PackageKind = iota //
	// A "binary" package is compiled or otherwise ready-to-use software.
	//
	// It describes a set of files inside a container image.
	PackageBinary // binary
	// A "source" package is software that must be compiled or otherwise
	// processed before it's ready to use.
	//
	// Conceptually, all "binary" packages come from a "source" package.
	// A single "source" package produces one or more other packages.
	//
	// It can be used to describe the set of packages produced from the source
	// package.
	PackageSource // source
	// A "layer" package is used to refer to a container layer itself.
	//
	// Conceptually, a "layer" package is a higher type that describes the
	// container image rather than the contents.
	PackageLayer // layer
	// An "ancestry" package is used to refer to a container layer and all
	// previous layers in an image.
	//
	// Conceptually, an "ancestry" package is a higher type that describes the
	// container image rather than the contents.
	PackageAncestry // ancestry
)
