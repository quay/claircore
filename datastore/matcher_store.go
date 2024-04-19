package datastore

// Iter is an iterator function that accepts a callback 'yield' to handle each
// iterator item. The consumer can signal the iterator to break or retry by
// returning an error. The iterator itself returns an error if the iteration
// cannot continue or was interrupted unexpectedly.
type Iter[T any] func(yield func(T, error) bool)

// MatcherStore aggregates all interface types
type MatcherStore interface {
	Updater
	Vulnerability
	Enrichment
}
