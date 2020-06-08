package claircore

import (
	"sort"
	"sync"
)

// AffectedManifests describes a set of manifests affected by
// a set of Vulnerabilities.
type AffectedManifests struct {
	mu sync.Mutex
	// map of vulnerabilities keyed by the vulnerability's ID
	Vulnerabilities map[string]*Vulnerability `json:"vulnerabilities"`
	// map associating a list of vulnerability ids keyed by the
	// manifest hash they affect.
	VulnerableManifests map[string][]string `json:"vulnerable_manifests"`
}

// NewAffectedManifests initializes a new AffectedManifests struct.
func NewAffectedManifests() AffectedManifests {
	return AffectedManifests{
		Vulnerabilities:     make(map[string]*Vulnerability),
		VulnerableManifests: make(map[string][]string),
	}
}

// Add will add the provided Vulnerability and Manifest digest
// to the necessary maps.
//
// Add is safe to use by multiple goroutines.
func (a *AffectedManifests) Add(v *Vulnerability, digests ...Digest) {
	a.mu.Lock()
	a.Vulnerabilities[v.ID] = v
	for _, d := range digests {
		hash := d.String()
		a.VulnerableManifests[hash] = append(a.VulnerableManifests[hash], v.ID)
	}
	a.mu.Unlock()
}

// Sort will sort each array in the VulnerableManifests map
// by Vulnerability.NormalizedSeverity in Desc order.
//
// Sort is safe to use by multiple goroutines.
func (a *AffectedManifests) Sort() {
	a.mu.Lock()
	for _, ids := range a.VulnerableManifests {
		sort.Slice(ids, func(i, j int) bool {
			id1, id2 := ids[i], ids[j]
			v1, v2 := a.Vulnerabilities[id1], a.Vulnerabilities[id2]
			// reverse this since we want descending sort
			return v1.NormalizedSeverity > v2.NormalizedSeverity
		})
	}
	a.mu.Unlock()
}
