package postgres

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
)

var _ scanner.Store = (*store)(nil)

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

func (s *store) ManifestScanned(ctx context.Context, hash string, scnrs scanner.VersionedScanners) (bool, error) {
	b, err := manifestScanned(ctx, s.db, hash, scnrs)
	return b, err
}

func (s *store) LayerScanned(ctx context.Context, hash string, scnr scanner.VersionedScanner) (bool, error) {
	b, err := layerScanned(ctx, s.db, hash, scnr)
	return b, err
}

func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, l *claircore.Layer, scnr scanner.VersionedScanner) error {
	err := indexPackages(ctx, s.db, s.pool, pkgs, l, scnr)
	return err
}

func (s *store) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, l *claircore.Layer, scnr scanner.VersionedScanner) error {
	err := indexDistributions(ctx, s.db, s.pool, dists, l, scnr)
	return err
}

func (s *store) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr scanner.VersionedScanner) error {
	err := indexRepositories(ctx, s.db, s.pool, repos, l, scnr)
	return err
}

func (s *store) PackagesByLayer(ctx context.Context, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Package, error) {
	pkgs, err := packagesByLayer(ctx, s.db, hash, scnrs)
	return pkgs, err
}

func (s *store) DistributionsByLayer(ctx context.Context, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Distribution, error) {
	dists, err := distributionsByLayer(ctx, s.db, hash, scnrs)
	return dists, err
}

func (s *store) RepositoriesByLayer(ctx context.Context, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Repository, error) {
	panic("not implemented")
}

func (s *store) RegisterScanners(ctx context.Context, scnrs scanner.VersionedScanners) error {
	err := registerScanners(ctx, s.db, scnrs)
	return err
}

func (s *store) ScanReport(ctx context.Context, hash string) (*claircore.ScanReport, bool, error) {
	sr, b, err := scanReport(ctx, s.db, hash)
	return sr, b, err
}

func (s *store) SetScanReport(ctx context.Context, sr *claircore.ScanReport) error {
	err := setScanReport(ctx, s.db, sr)
	return err
}

func (s *store) SetScanFinished(ctx context.Context, sr *claircore.ScanReport, scnrs scanner.VersionedScanners) error {
	err := setScanFinished(ctx, s.db, sr, scnrs)
	return err
}
