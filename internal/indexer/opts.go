package indexer

import "github.com/quay/claircore/pkg/distlock"

// Opts are options to instantiate a indexer
type Opts struct {
	Store        Store
	ScanLock     distlock.Locker
	LayerScanner LayerScanner
	Fetcher      Fetcher
	Ecosystems   []*Ecosystem
	Vscnrs       VersionedScanners
}
