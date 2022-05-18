package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// Store is an interface for dealing with objects libindex needs to persist.
// Stores may be implemented per storage backend.
type Store interface {
	Setter
	Querier
	Indexer
	// Close frees any resources associated with the Store.
	Close(context.Context) error
}

// Setter interface provides the method set for required marking events, or registering
// components, associated with an Index operation.
type Setter interface {
	// PersistManifest must store the presence of a manifest and it's layers into the system.
	//
	// Typically this will write into identity tables so later methods have a foreign key
	// to reference and data integrity is applied.
	PersistManifest(ctx context.Context, manifest claircore.Manifest) error
	// DeleteManifests removes the manifests indicated by the passed digests
	// from the backing store.
	DeleteManifests(context.Context, ...claircore.Digest) ([]claircore.Digest, error)

	// SetLayerScanned marks the provided layer hash successfully scanned by the provided versioned scanner.
	//
	// After this method is returned a call to Querier.LayerScanned with the same arguments must return true.
	SetLayerScanned(ctx context.Context, hash claircore.Digest, scnr VersionedScanner) error
	// RegisterPackageScanners registers the provided scanners with the persistence layer.
	RegisterScanners(ctx context.Context, scnrs VersionedScanners) error
	// SetIndexReport persists the current state of the IndexReport.
	//
	// IndexReports maybe in intermediate states to provide feedback for clients. this method should be
	// used to communicate scanning state updates. to signal the scan has completely successfully
	// see SetIndexFinished.
	SetIndexReport(context.Context, *claircore.IndexReport) error
	// SetIndexFinished marks a scan successfully completed.
	//
	// After this method returns a call to Querier.ManifestScanned with the manifest hash represted in the provided IndexReport
	// must return true.
	//
	// Also a call to Querier.IndexReport with the manifest hash represted in the provided IndexReport must return the IndexReport
	// in finished state.
	SetIndexFinished(ctx context.Context, sr *claircore.IndexReport, scnrs VersionedScanners) error
}

// Querier interface provides the method set to ascertain indexed artifacts and query whether a layer
// or manifest has been scanned.
type Querier interface {
	// ManifestScanned returns whether the given manifest was scanned by the provided scanners.
	ManifestScanned(ctx context.Context, hash claircore.Digest, scnrs VersionedScanners) (bool, error)
	// LayerScanned returns whether the given layer was scanned by the provided scanner.
	LayerScanned(ctx context.Context, hash claircore.Digest, scnr VersionedScanner) (bool, error)
	// PackagesByLayer gets all the packages found in a layer limited by the provided scanners.
	PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs VersionedScanners) ([]*claircore.Package, error)
	// DistributionsByLayer gets all the distributions found in a layer limited by the provided scanners.
	DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs VersionedScanners) ([]*claircore.Distribution, error)
	// RepositoriesByLayer gets all the repositories found in a layer limited by the provided scanners.
	RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs VersionedScanners) ([]*claircore.Repository, error)
	// IndexReport attempts to retrieve a persisted IndexReport.
	IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error)
	// AffectedManifests returns a list of manifest digests which the target vulnerability
	// affects.
	AffectedManifests(ctx context.Context, v claircore.Vulnerability, f claircore.CheckVulnernableFunc) ([]claircore.Digest, error)
}

// Indexer interface provide the method set required for indexing layer and manifest contents into
// a persistent store.
type Indexer interface {
	// IndexPackages indexes a package into the persistence layer.
	IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr VersionedScanner) error
	// IndexDistributions indexes distributions into the persistence layer.
	IndexDistributions(ctx context.Context, dists []*claircore.Distribution, layer *claircore.Layer, scnr VersionedScanner) error
	// IndexRepositories indexes repositories into the persistence layer.
	IndexRepositories(ctx context.Context, repos []*claircore.Repository, layer *claircore.Layer, scnr VersionedScanner) error
	// IndexManifest should index the coalesced manifest's content given an IndexReport.
	IndexManifest(ctx context.Context, ir *claircore.IndexReport) error
}
