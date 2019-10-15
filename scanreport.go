package claircore

// ScanRecord represents a Package and it's associated Distribution and
// Repository information
type ScanRecord struct {
	Package      *Package
	Distribution *Distribution
	Repository   *Repository
}

// ScanReport provides the found packages, distributions, and repositories in a layer and
// their assocations with a particular package.
type ScanReport struct {
	// the manifest hash this scan result is assocaited with
	Hash string `json:"manifest_hash"`
	// the current state of the scan.
	State string `json:"state"`
	// packages found after applying all layers
	Packages map[int]*Package `json:"packages"`
	// distributions found after applying all layers
	Distributions map[int]*Distribution `json:"distributions"`
	// repositories found after applying all layers
	Repositories map[int]*Repository `json:"repository"`
	// PackagesByDistribution maps a package id to it's associated distribution id
	DistributionByPackage map[int]int `json:"distributionByPackage"`
	// PackagesByRepositories maps a package id to it's associated repository id
	RepositoryByPackage map[int]int `json:"packagesByRepositories"`
	// layer hash that introduced the given package id
	PackageIntroduced map[int]string `json:"packageIntroduced"`
	// whether the scan was successful
	Success bool `json:"success"`
	// the first fatal error that occured during a scan process
	Err string `json:"err"`
}

// ScanRecords returns a list of ScanRecords derived from the ScanReport
// If a value in the ScanRecord is not found in the ScanReport the empty value
// is returned
func (report *ScanReport) ScanRecords() []*ScanRecord {
	out := []*ScanRecord{}
	for _, pkg := range report.Packages {
		record := &ScanRecord{}
		record.Package = pkg

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
