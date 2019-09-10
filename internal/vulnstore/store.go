package vulnstore

// Store aggregates all interface types
type Store interface {
	Updater
	Vulnerability
}
