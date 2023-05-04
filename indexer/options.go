package indexer

import (
	"net/http"
)

// Options are options to instantiate a indexer
type Options struct {
	Client        *http.Client
	ScannerConfig struct {
		Package, Dist, Repo, File map[string]func(interface{}) error
	}
	Store        Store
	LayerScanner *LayerScanner
	FetchArena   FetchArena
	Ecosystems   []*Ecosystem
	Resolvers    []Resolver
	Vscnrs       VersionedScanners
}
