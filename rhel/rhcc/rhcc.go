// Package rhcc implements an ecosystem for the Red Hat Container Catalog.
//
// This ecosystem treats an entire container as a package and matches advisories
// against it.
package rhcc

import (
	"errors"

	"github.com/quay/claircore"
)

// RepositoryKey should be used for every indexed repository coming from this package. It is
// used when persisting Red Hat VEX data pertaining to container images and referenced in the
// RHCC matching logic.
const RepositoryKey = "rhcc-container-repository"

var (
	// GoldRepo is the claircore.Repository that RHCC index record are associated with when
	// the image has been build via the legacy Red Hat build system. With newer images, reliable
	// repository CPEs are available and can be used in lieu of the GoldRepo.
	GoldRepo = claircore.Repository{
		Name: "Red Hat Container Catalog",
		URI:  `https://catalog.redhat.com/software/containers/explore`,
		Key:  RepositoryKey,
	}
	errNotFound = errors.New("not found")
)
