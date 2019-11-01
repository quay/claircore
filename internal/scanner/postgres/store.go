package postgres

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/pkg/tracing"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/api/trace"
	apitrace "go.opentelemetry.io/api/trace"
)

var _ scanner.Store = (*store)(nil)

// store implements the claircore.Store interface.
// implements all persistence features
type store struct {
	db *sqlx.DB
	// lower level access to the pgx pool
	pool *pgxpool.Pool
	// the tracer to use with this store
	tracer trace.Tracer
}

// NewStore constructs a new Postgres Store with a default tracer
func NewStore(db *sqlx.DB, pool *pgxpool.Pool) *store {
	return WithTracer(db, pool, tracing.GetTracer("claircore/store/postgres"))
}

// WithTracer constructs a new Postgres Store with the given tracer instead of the default one
func WithTracer(db *sqlx.DB, pool *pgxpool.Pool, tracer apitrace.Tracer) *store {
	return &store{
		db:     db,
		pool:   pool,
		tracer: tracer,
	}
}

func (s *store) ManifestScanned(ctx context.Context, hash string, scnrs scanner.VersionedScanners) (bool, error) {
	ctx, span := s.tracer.Start(ctx, "ManifestScanned")
	defer span.End()

	b, err := manifestScanned(ctx, s.db, hash, scnrs)
	return b, tracing.HandleError(err, span)
}

func (s *store) LayerScanned(ctx context.Context, hash string, scnr scanner.VersionedScanner) (bool, error) {
	ctx, span := s.tracer.Start(ctx, "LayerScanned")
	defer span.End()

	b, err := layerScanned(ctx, s.db, hash, scnr)
	return b, tracing.HandleError(err, span)
}

func (s *store) IndexPackages(ctx context.Context, pkgs []*claircore.Package, l *claircore.Layer, scnr scanner.VersionedScanner) error {
	ctx, span := s.tracer.Start(ctx, "IndexPackages")
	defer span.End()

	err := indexPackages(ctx, s.db, s.pool, pkgs, l, scnr)
	return tracing.HandleError(err, span)
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
	ctx, span := s.tracer.Start(ctx, "PackagesByLayer")
	defer span.End()

	pkgs, err := packagesByLayer(ctx, s.db, hash, scnrs)
	return pkgs, tracing.HandleError(err, span)
}

func (s *store) DistributionsByLayer(ctx context.Context, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Distribution, error) {
	dists, err := distributionsByLayer(ctx, s.db, hash, scnrs)
	return dists, err
}

func (s *store) RepositoriesByLayer(ctx context.Context, hash string, scnrs scanner.VersionedScanners) ([]*claircore.Repository, error) {
	repos, err := repositoriesByLayer(ctx, s.db, hash, scnrs)
	return repos, err
}

func (s *store) RegisterScanners(ctx context.Context, scnrs scanner.VersionedScanners) error {
	ctx, span := s.tracer.Start(ctx, "RegisterScanners")
	defer span.End()

	err := registerScanners(ctx, s.db, scnrs)
	return tracing.HandleError(err, span)
}

func (s *store) ScanReport(ctx context.Context, hash string) (*claircore.ScanReport, bool, error) {
	ctx, span := s.tracer.Start(ctx, "ScanReport")
	defer span.End()

	sr, b, err := scanReport(ctx, s.db, hash)
	return sr, b, tracing.HandleError(err, span)
}

func (s *store) SetScanReport(ctx context.Context, sr *claircore.ScanReport) error {
	ctx, span := s.tracer.Start(ctx, "SetScanReport")
	defer span.End()

	err := setScanReport(ctx, s.db, sr)
	return tracing.HandleError(err, span)
}

func (s *store) SetScanFinished(ctx context.Context, sr *claircore.ScanReport, scnrs scanner.VersionedScanners) error {
	ctx, span := s.tracer.Start(ctx, "SetScanFinished")
	defer span.End()

	err := setScanFinished(ctx, s.db, sr, scnrs)
	return tracing.HandleError(err, span)
}
