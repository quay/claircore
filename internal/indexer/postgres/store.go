package postgres

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

var _ indexer.Store = (*store)(nil)

// store implements the claircore.Store interface.
// implements all persistence features
type store struct {
	db *sqlx.DB
	// lower level access to the pgx pool
	pool *pgxpool.Pool
}

func NewStore(db *sqlx.DB, pool *pgxpool.Pool) *store {
	return &store{
		db:   db,
		pool: pool,
	}
}

func (s *store) Close(_ context.Context) error {
	s.pool.Close()
	return s.db.Close()
}

func (s *store) PersistManifest(ctx context.Context, manifest claircore.Manifest) error {
	err := persistManifest(ctx, s.pool, manifest)
	return err
}

func (s *store) ManifestScanned(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) (bool, error) {
	b, err := manifestScanned(ctx, s.db, hash, scnrs)
	return b, err
}

func (s *store) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	b, err := layerScanned(ctx, s.pool, hash, scnr)
	return b, err
}

func (s *store) SetLayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) error {
	err := setLayerScanned(ctx, s.pool, hash, scnr)
	return err
}

func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	err := indexPackages(ctx, s.pool, pkgs, l, scnr)
	return err
}

func (s *store) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	err := indexDistributions(ctx, s.db, s.pool, dists, l, scnr)
	return err
}

func (s *store) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	err := indexRepositories(ctx, s.db, s.pool, repos, l, scnr)
	return err
}

func (s *store) IndexManifest(ctx context.Context, ir *claircore.IndexReport) error {
	err := indexManifest(ctx, s.pool, ir)
	return err
}

func (s *store) PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Package, error) {
	pkgs, err := packagesByLayer(ctx, s.db, hash, scnrs)
	return pkgs, err
}

func (s *store) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	dists, err := distributionsByLayer(ctx, s.db, hash, scnrs)
	return dists, err
}

func (s *store) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	repos, err := repositoriesByLayer(ctx, s.db, hash, scnrs)
	return repos, err
}

func (s *store) RegisterScanners(ctx context.Context, scnrs indexer.VersionedScanners) error {
	err := registerScanners(ctx, s.db, scnrs)
	return err
}

func (s *store) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	sr, b, err := indexReport(ctx, s.db, hash)
	return sr, b, err
}

func (s *store) AffectedManifests(ctx context.Context, v claircore.Vulnerability) ([]claircore.Digest, error) {
	hashes, err := affectedManifests(ctx, s.pool, v)
	return hashes, err
}

func (s *store) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	err := setIndexReport(ctx, s.db, ir)
	return err
}

func (s *store) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	err := setScanFinished(ctx, s.db, ir, scnrs)
	return err
}
