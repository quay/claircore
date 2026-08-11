package jsonblob

import (
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	vulnerability sync.Pool
	enrichment    sync.Pool
)

func getVulnerability() *claircore.Vulnerability {
	if v := vulnerability.Get(); v != nil {
		return v.(*claircore.Vulnerability)
	}
	return new(claircore.Vulnerability)
}

// ReturnVulnerability can be used by callers to return
// [claircore.Vulnerability] objects from [Loader.All] iterators to a common
// pool.
//
// This may take some pressure off the garbage collector.
func ReturnVulnerability(v *claircore.Vulnerability) {
	// Reset the fields.
	*v = claircore.Vulnerability{}
	vulnerability.Put(v)
}

func getEnrichment() *driver.EnrichmentRecord {
	if v := enrichment.Get(); v != nil {
		return v.(*driver.EnrichmentRecord)
	}
	return new(driver.EnrichmentRecord)
}

// ReturnEnrichment can be used by callers to return [driver.EnrichmentRecord]
// objects from [Loader.All] iterators to a common pool.
//
// This may take some pressure off the garbage collector.
func ReturnEnrichment(e *driver.EnrichmentRecord) {
	// Reset the fields.
	*e = driver.EnrichmentRecord{}
	enrichment.Put(e)
}
