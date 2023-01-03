package indexer

import (
	"net/http"
)

// Opts are options to instantiate a indexer
type Opts struct {
	Client        *http.Client
	ScannerConfig struct {
		Package, Dist, Repo map[string]func(interface{}) error
	}
	Store        Store
	LayerScanner LayerScanner
	Realizer     Realizer
	Ecosystems   []*Ecosystem
	Vscnrs       VersionedScanners
	// Deprecated: the airgap functionality should be encapsulated in the client passed to libindex.New()
	Airgap bool
}
