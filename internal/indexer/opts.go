package indexer

import (
	"net/http"

	"github.com/quay/claircore/pkg/distlock"
)

// Opts are options to instantiate a indexer
type Opts struct {
	Store         Store
	ScanLock      distlock.Locker
	LayerScanner  LayerScanner
	Fetcher       Fetcher
	Ecosystems    []*Ecosystem
	Vscnrs        VersionedScanners
	Airgap        bool
	Client        *http.Client
	ScannerConfig struct {
		Package, Dist, Repo map[string]func(interface{}) error
	}
}
