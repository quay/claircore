package vulnstore

import "github.com/quay/claircore"

// Updater is an interface exporting the necessary methods
// for updating a vulnerability database
type Updater interface {
	// GetHash should retrieve the latest value that the updater identified by a unique key
	// key will often be a claircore.Updater's unique name
	GetHash(key string) (string, error)
	// PutVulnerabilities should write the given vulnerabilties to the database and associate
	// these vulnerabilities with the updater and the newest update hash
	PutVulnerabilities(updater string, hash string, vulns []*claircore.Vulnerability) error
}
