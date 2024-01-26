package datastore

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// IndexerV1 is an interface for dealing with objects
// [github.com/quay/claircore/libindex.Libindex] needs to persist.
type IndexerV1 interface {
	IndexerV1Setter
	IndexerV1Querier
	IndexerV1Artifact
	// Close frees any resources associated with the Store.
	//
	// Consult the concrete type's documentation on whether any resources passed
	// need to be closed independently or not.
	Close(context.Context) error
}

// IndexerV1Setter interface provides the method set for required marking
// events, or registering components, associated with an Index operation.
type IndexerV1Setter interface {
	// PersistManifest records the presence of a manifest and its layers into the
	// backing store.
	//
	// Typically this will write into identity tables so later methods have a
	// foreign key to reference and data integrity is maintained.
	PersistManifest(context.Context, claircore.Manifest) error
	// DeleteManifests removes the manifests indicated by the passed digests
	// from the backing store.
	DeleteManifests(context.Context, ...claircore.Digest) ([]claircore.Digest, error)
	// SetLayerScanned marks the provided layer hash as successfully scanned by
	// the provided VersionedScanner.
	//
	// After this method has returned, a call to an IndexerV1Querier.LayerScanned
	// configured with the same backing store and the same arguments will return
	// true.
	SetLayerScanned(context.Context, claircore.Digest, indexer.VersionedScanner) error
	// RegisterPackageScanners registers the provided scanners with the
	// backing store.
	RegisterScanners(context.Context, indexer.VersionedScanners) error
	// SetIndexReport persists the current state of the IndexReport.
	//
	// IndexReports may be in intermediate states to provide feedback for
	// clients. This method should be used to communicate scanning state
	// updates. To signal the indexing process has completed successfully, see
	// SetIndexFinished.
	SetIndexReport(context.Context, *claircore.IndexReport) error
	// SetIndexFinished marks an indexing process as completed successfully.
	//
	// Assuming an IndexerV1Querier configured with the same backing store, when
	// this method returning without an error, a call to ManifestScanned with
	// the IndexReport's manifest digest will return true. Similarly, a call to
	// IndexReport with the IndexReport's manifest digest will return the
	// IndexReport in finished state.
	SetIndexFinished(context.Context, *claircore.IndexReport, indexer.VersionedScanners) error
}

// IndexerV1Querier interface provides accessors for indexed artifacts and query
// whether a layer or manifest has been indexed.
type IndexerV1Querier interface {
	// ManifestScanned returns whether the specified manifest was indexed by the
	// provided VersionedScanners.
	ManifestScanned(context.Context, claircore.Digest, indexer.VersionedScanners) (bool, error)
	// LayerScanned returns whether the specified layer was indexed by the
	// provided VersionedScanner.
	LayerScanned(context.Context, claircore.Digest, indexer.VersionedScanner) (bool, error)
	// PackagesByLayer gets all the packages found in the specified layer
	// limited by the provided VersionedScanners.
	PackagesByLayer(context.Context, claircore.Digest, indexer.VersionedScanners) ([]*claircore.Package, error)
	// DistributionsByLayer gets all the distributions found in the specified
	// layer limited by the provided VersionedScanners.
	DistributionsByLayer(context.Context, claircore.Digest, indexer.VersionedScanners) ([]*claircore.Distribution, error)
	// RepositoriesByLayer gets all the repositories found in the specified
	// layer limited by the provided VersionedScanners.
	RepositoriesByLayer(context.Context, claircore.Digest, indexer.VersionedScanners) ([]*claircore.Repository, error)
	// FilesByLayer gets all the interesting files found in the specified layer
	// limited by the provided VersionedScanners.
	FilesByLayer(context.Context, claircore.Digest, indexer.VersionedScanners) ([]claircore.File, error)
	// IndexReport attempts to retrieve a persisted IndexReport, reporting
	// whether it exists or not.
	IndexReport(context.Context, claircore.Digest) (*claircore.IndexReport, bool, error)
	// AffectedManifests returns a slice of manifest digests which the target vulnerability
	// affects.
	AffectedManifests(context.Context, claircore.Vulnerability, claircore.CheckVulnernableFunc) ([]claircore.Digest, error)
}

// IndexerV1Artifact interface provides methods for indexing
// layer and manifest contents into a backing store.
type IndexerV1Artifact interface {
	// IndexPackages indexes a package into the backing store.
	IndexPackages(context.Context, []*claircore.Package, *claircore.Layer, indexer.VersionedScanner) error
	// IndexDistributions indexes distributions into the backing store.
	IndexDistributions(context.Context, []*claircore.Distribution, *claircore.Layer, indexer.VersionedScanner) error
	// IndexRepositories indexes repositories into the backing store.
	IndexRepositories(context.Context, []*claircore.Repository, *claircore.Layer, indexer.VersionedScanner) error
	// IndexFiles indexes the interesting files into the backing store.
	IndexFiles(context.Context, []claircore.File, *claircore.Layer, indexer.VersionedScanner) error
	// IndexManifest should index the coalesced manifest's content given an IndexReport.
	IndexManifest(context.Context, *claircore.IndexReport) error
}
