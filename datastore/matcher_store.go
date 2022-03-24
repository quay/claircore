package datastore

// Store aggregates all interface types
type MatcherStore interface {
	Updater
	Vulnerability
	Enrichment
}
