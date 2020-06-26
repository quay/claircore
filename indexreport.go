package claircore

// IndexRecord is an entry in the IndexReport.
//
// IndexRecords provide full access to contextual package
// structures such as Distribution and Repository.
//
// A list of these can be thought of as an "unpacked" IndexReport
type IndexRecord struct {
	Package      *Package
	Distribution *Distribution
	Repository   *Repository
}

// IndexReport provides a database for discovered artifacts in an image.
//
// IndexReports make heavy usage of lookup maps to associate information
// without repetition.
type IndexReport struct {
	// the manifest hash this IndexReport is describing
	Hash Digest `json:"manifest_hash"`
	// the current state of the index operation
	State string `json:"state"`
	// all discovered packages in this manifest key'd by package id
	Packages map[string]*Package `json:"packages"`
	// all discovered distributions in this manifest key'd by distribution id
	Distributions map[string]*Distribution `json:"distributions"`
	// all discovered repositories in this manifest key'd by repository id
	Repositories map[string]*Repository `json:"repository"`
	// a list of environment details a package was discovered in key'd by package id
	Environments map[string][]*Environment `json:"environments"`
	// whether the index operation finished successfully
	Success bool `json:"success"`
	// an error string in the case the index did not succeed
	Err string `json:"err"`
}

// IndexRecords returns a list of IndexRecords derived from the IndexReport
func (report *IndexReport) IndexRecords() []*IndexRecord {
	out := []*IndexRecord{}
	for _, pkg := range report.Packages {
		for _, env := range report.Environments[pkg.ID] {
			if len(env.RepositoryIDs) == 0 {
				record := &IndexRecord{}
				record.Package = pkg
				record.Distribution = report.Distributions[env.DistributionID]
				out = append(out, record)
				continue
			}
			// create package record for each repository
			for _, repositoryID := range env.RepositoryIDs {
				record := &IndexRecord{}
				record.Package = pkg
				record.Distribution = report.Distributions[env.DistributionID]
				record.Repository = report.Repositories[repositoryID]
				out = append(out, record)
			}
		}
	}
	return out
}
