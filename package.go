package claircore

import "github.com/quay/claircore/pkg/cpe"

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind string `json:"kind,omitempty"`
	// if type is a binary package a source package maybe present which built this binary package.
	// must be a pointer to support recursive type:
	Source *Package `json:"source,omitempty"`
	// the file system path or prefix where this package resides
	PackageDB string `json:"-"`
	// a hint on which repository this package was downloaded from
	RepositoryHint string `json:"-"`
	// NormalizedVersion is a representation of a version string that's
	// correctly ordered when compared with other representations from the same
	// producer.
	NormalizedVersion Version `json:"normalized_version,omitempty"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
	// CPE name for package
	CPE cpe.WFN `json:"cpe,omitempty"`
}

const (
	BINARY = "binary"
	SOURCE = "source"
)
