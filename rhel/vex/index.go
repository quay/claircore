package vex

import "github.com/quay/claircore/toolkit/types/csaf"

// IndexByID implements an index for a string ID to an arbitrary type.
//
// Meant to be used to build indexes over [csaf.CSAF] documents.
type indexByID[T any] struct {
	index    map[string]*T
	populate func(map[string]*T, *csaf.CSAF)
}

// NewIndexByID constructs an indexByID.
func newIndexByID[T any](populate func(map[string]*T, *csaf.CSAF)) *indexByID[T] {
	return &indexByID[T]{
		index:    make(map[string]*T),
		populate: populate,
	}
}

// Reset populates the index for the provided document, reusing any allocated
// memory.
func (c *indexByID[T]) Reset(doc *csaf.CSAF) {
	clear(c.index)
	c.populate(c.index, doc)
}

// Get returns the entry for the ID if present.
func (c *indexByID[T]) Get(id string) *T {
	return c.index[id]
}

// ProductIndex is an index of "product_id_t" to "full_product_name_t".
type productIndex = indexByID[csaf.Product]

// NewProductIndex constructs a productIndex.
func newProductIndex() *productIndex {
	return newIndexByID(populateProducts)
}

// PopulateProducts is the populate function for a productIndex.
func populateProducts(m map[string]*csaf.Product, doc *csaf.CSAF) {
	var walk func(*csaf.ProductBranch)
	walk = func(b *csaf.ProductBranch) {
		m[b.Product.ID] = &b.Product
		for i := range b.Branches {
			walk(&b.Branches[i])
		}
	}
	walk(&doc.ProductTree)
}

// ScoreIndex is an index of "product_id_t" to "score object".
type scoreIndex = indexByID[csaf.Score]

// NewScoreIndex constructs a scoreIndex.
func newScoreIndex() *scoreIndex {
	return newIndexByID(populateScores)
}

// PopulateScores is the populate function for a scoreIndex.
func populateScores(m map[string]*csaf.Score, doc *csaf.CSAF) {
	for i := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[i]
		for i := range v.Scores {
			s := &v.Scores[i]
			for _, id := range s.ProductIDs {
				m[id] = s
			}
		}
	}
}

// ThreatImpactIndex is an index of "product_id_t" to "threat object" with the
// category "impact".
type threatImpactIndex = indexByID[csaf.ThreatData]

// NewThreatImpactIndex constructs a threatImpactIndex.
func newThreatImpactIndex() *threatImpactIndex {
	return newIndexByID(populateThreats("impact"))
}

// PopulateThreats returns a populate function for [csaf.ThreatData] of the
// indicated category.
func populateThreats(category string) func(map[string]*csaf.ThreatData, *csaf.CSAF) {
	return func(m map[string]*csaf.ThreatData, doc *csaf.CSAF) {
		for i := range doc.Vulnerabilities {
			v := &doc.Vulnerabilities[i]
			for i := range v.Threats {
				t := &v.Threats[i]
				if t.Category != category {
					continue
				}
				for _, id := range t.ProductIDs {
					m[id] = t
				}
			}
		}
	}
}

// RemediationIndex is an index of "product_id_t" to "remediation object".
type remediationIndex = indexByID[csaf.RemediationData]

// NewRemediationIndex constructs a remediationIndex.
func newRemediationIndex() *remediationIndex {
	return newIndexByID(populateRemediations)
}

// PopulateRemediations is the populate function for a remediationIndex.
func populateRemediations(m map[string]*csaf.RemediationData, doc *csaf.CSAF) {
	for i := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[i]
		for i := range v.Remediations {
			r := &v.Remediations[i]
			for _, id := range r.ProductIDs {
				m[id] = r
			}
		}
	}
}

// DefaultComponentIndex is an index of "product_id_t" to "relationship object"
// with a "default_component_of" category.
type defaultComponentIndex = indexByID[csaf.Relationship]

// NewDefaultComponentIndex constructs a defaultComponentIndex.
func newDefaultComponentIndex() *defaultComponentIndex {
	return newIndexByID(populateRelationships("default_component_of"))
}

// PopulateRelationships returns a populate function for [csaf.Relationship] of
// the indicated category.
func populateRelationships(category string) func(map[string]*csaf.Relationship, *csaf.CSAF) {
	return func(m map[string]*csaf.Relationship, doc *csaf.CSAF) {
		rs := doc.ProductTree.Relationships
		for i := range rs {
			r := &rs[i]
			if r.Category != category {
				continue
			}
			m[r.FullProductName.ID] = r
		}
	}
}
