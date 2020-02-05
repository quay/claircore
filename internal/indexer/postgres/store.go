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

func (s *store) ManifestScanned(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) (bool, error) {
	b, err := manifestScanned(ctx, s.db, hash, scnrs)
	return b, err
}

func (s *store) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	b, err := layerScanned(ctx, s.db, hash, scnr)
	return b, err
}

func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	err := indexPackages(ctx, s.db, s.pool, pkgs, l, scnr)
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

func (s *store) SetIndexReport(ctx context.Context, sr *claircore.IndexReport) error {
	err := setIndexReport(ctx, s.db, sr)
	return err
}

func (s *store) SetIndexFinished(ctx context.Context, sr *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	err := setScanFinished(ctx, s.db, sr, scnrs)
	return err
}
