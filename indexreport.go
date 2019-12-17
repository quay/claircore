package claircore

// IndexRecord is an entry in the IndexReport.
//
// A IndexRecord identifies a discovered package along with its
// Distribution and Repository information if present.
type IndexRecord struct {
	Package      *Package
	Distribution *Distribution
	Repository   *Repository
}

// IndexReport provides a package database for a container image.
//
// A IndexReport is used to inventory a discrete package information found
// within in each layer of a container image.
type IndexReport struct {
	// the manifest hash this scan result is assocaited with
	Hash string `json:"manifest_hash"`
	// the current state of the scan.
	State string `json:"state"`
	// a map, keyed by package ID, identifying all discovered packages in an image
	Packages map[int]*Package `json:"packages"`
	// a map, keyed by package id providing contexts where a package was discovered
	Details map[int][]*Details `json:"details"`
	// distributions found after applying all layers
	Distributions map[int]*Distribution `json:"distributions"`
	// repositories found after applying all layers
	Repositories map[int]*Repository `json:"repository"`
	// PackagesByDistribution maps a package id to it's associated distribution id
	DistributionByPackage map[int]int `json:"distribution_by_package"`
	// PackagesByRepositories maps a package id to it's associated repository id
	RepositoryByPackage map[int]int `json:"repository_by_package"`
	// layer hash that introduced the given package id
	PackageIntroduced map[int]string `json:"package_introduced"`
	// whether the scan was successful
	Success bool `json:"success"`
	// the first fatal error that occured during a scan process
	Err string `json:"err"`
}

// IndexRecords returns a list of IndexRecords derived from the IndexReport
//
// If a field in the IndexRecord is not found in the IndexReport the empty value
// is returned to provide nil safey.
func (report *IndexReport) IndexRecords() []*IndexRecord {
	out := []*IndexRecord{}
	for _, pkg := range report.Packages {
		record := &IndexRecord{}
		record.Package = pkg

		if record.Package.Source == nil {
			record.Package.Source = &Package{}
		}

		if id, ok := report.DistributionByPackage[pkg.ID]; ok {
			record.Distribution = report.Distributions[id]
		} else {
			record.Distribution = &Distribution{}
		}

		if id, ok := report.RepositoryByPackage[pkg.ID]; ok {
			record.Repository = report.Repositories[id]
		} else {
			record.Repository = &Repository{}
		}
		out = append(out, record)
	}
	return out
}
