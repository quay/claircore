package postgres

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
)

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

func (s *store) ManifestScanned(hash string, scnrs scanner.VersionedScanners) (bool, error) {
	b, err := manifestScanned(s.db, hash, scnrs)
	return b, err
}

func (s *store) LayerScanned(hash string, scnr scanner.VersionedScanner) (bool, error) {
	b, err := layerScanned(s.db, hash, scnr)
	return b, err
}

func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, l *claircore.Layer, scnr scanner.VersionedScanner) error {
	err := indexPackages(ctx, s.db, s.pool, pkgs, l, scnr)
	return err
}

func (s *store) PackagesByLayer(hash string, scnrs scanner.VersionedScanners) ([]*claircore.Package, error) {
	pkgs, err := packagesByLayer(s.db, hash, scnrs)
	return pkgs, err
}

func (s *store) RegisterScanners(scnrs scanner.VersionedScanners) error {
	err := registerScanners(s.db, scnrs)
	return err
}

func (s *store) ScanReport(hash string) (*claircore.ScanReport, bool, error) {
	sr, b, err := scanReport(s.db, hash)
	return sr, b, err
}

func (s *store) SetScanReport(sr *claircore.ScanReport) error {
	err := setScanReport(s.db, sr)
	return err
}

func (s *store) SetScanFinished(sr *claircore.ScanReport, scnrs scanner.VersionedScanners) error {
	err := setScanFinished(s.db, sr, scnrs)
	return err
}
