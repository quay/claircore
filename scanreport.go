package claircore

// ScanRecord is an entry in the ScanReport.
//
// A ScanRecord identifies a discovered package along with its
// Distribution and Repository information if present.
type ScanRecord struct {
	Package      *Package
	Distribution *Distribution
	Repository   *Repository
}

// ScanReport provides a package database for a container image.
//
// A ScanReport is used to inventory a discrete package information found
// within in each layer of a container image.
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

// ScanRecords returns a list of ScanRecords derived from the ScanReport
//
// If a field in the ScanRecord is not found in the ScanReport the empty value
// is returned to provide nil safey.
func (report *ScanReport) ScanRecords() []*ScanRecord {
	out := []*ScanRecord{}
	for _, pkg := range report.Packages {
		record := &ScanRecord{}
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
