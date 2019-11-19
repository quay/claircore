package indexer

import "github.com/quay/claircore"

type RepositoryScanner interface {
	VersionedScanner
	Scan(*claircore.Layer) ([]*claircore.Repository, error)
}
