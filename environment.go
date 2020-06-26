package claircore

// Environment describes the surrounding environment a package was
// discovered in.
//
// Environment must be accompanied by a parent structure which maps
// IDs to data models in order to have meaning. In our case this is
// IndexReport or VulnerabilityReport.
type Environment struct {
	// the package database the associated package was discovered in
	PackageDB string `json:"package_db"`
	// the layer in which the associated package was introduced
	IntroducedIn Digest `json:"introduced_in"`
	// the ID of the distribution the package was discovered on
	DistributionID string `json:"distribution_id"`
	// the ID of the repository where this package was downloaded from (currently not used)
	RepositoryIDs []string `json:"repository_ids"`
}
