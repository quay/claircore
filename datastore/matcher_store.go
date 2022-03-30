package datastore

// MatcherStore aggregates all interface types
type MatcherStore interface {
	Updater
	Vulnerability
	Enrichment
}
