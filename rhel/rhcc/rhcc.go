// Package rhcc implements an ecosystem for the Red Hat Container Catalog.
//
// This ecosystem treats an entire container as a package and matches advisories
// against it.
package rhcc

import (
	"github.com/quay/claircore"
)

// GoldRepo is the claircore.Repository that every RHCC index record is associated with.
// It is also the claircore.Repository that is associated with OCI VEX vulnerabilities.
var GoldRepo = claircore.Repository{
	Name: "Red Hat Container Catalog",
	URI:  `https://catalog.redhat.com/software/containers/explore`,
}
