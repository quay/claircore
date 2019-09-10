package claircore

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID int `json:"id"`
	// concatenated name:version string
	NameVersion string `json:"name_version"`
	// the name of the distribution
	Name string `json:"name"`
	// the version of the distribution
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind string `json:"kind"`
	// if type is a binary package a source package maybe present which built this binary package.
	// must be a pointer to support recursive type:
	Source *Package `json:"source"`
	// the distribution information for this package. this will be used to appropriately link CVE data to this
	// package
	Dist *Distribution `json:"dist"`
}
