package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/microbatch"
	"github.com/quay/zlog"
)

var (
	ErrNotIndexed               = fmt.Errorf("vulnerability containers data not indexed by any scannners")
	_             indexer.Store = (*IndexerStore)(nil)
)

// InitPostgresIndexerStore initialize a indexer.Store given the pgxpool.Pool
func InitPostgresIndexerStore(_ context.Context, pool *pgxpool.Pool, doMigration bool) (indexer.Store, error) {
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer db.Close()

	// do migrations if requested
	if doMigration {
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.IndexerMigrationTable
		err := migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	store := NewIndexerStore(pool)
	return store, nil
}

// IndexerStore implements the claircore.Store interface.
//
// All the other exported methods live in their own files.
type IndexerStore struct {
	pool *pgxpool.Pool
}

func NewIndexerStore(pool *pgxpool.Pool) *IndexerStore {
	return &IndexerStore{
		pool: pool,
	}
}

func (s *IndexerStore) Close(_ context.Context) error {
	s.pool.Close()
	return nil
}

func (s *IndexerStore) selectScanners(ctx context.Context, vs indexer.VersionedScanners) ([]int64, error) {
	ids := make([]int64, len(vs))
	var err error
	selectScanner := newQuery(ctx, "indexer", "select_scanner")
	for i, v := range vs {
		defer selectScanner.Start(&err)()
		err = s.pool.QueryRow(ctx, selectScanner.SQL, v.Name(), v.Version(), v.Kind()).
			Scan(&ids[i])
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve id for scanner %q: %w", v.Name(), err)
		}
	}

	return ids, nil
}

func (s *IndexerStore) IndexManifest(ctx context.Context, ir *claircore.IndexReport) error {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexManifest")

	if ir.Hash.String() == "" {
		return fmt.Errorf("received empty hash. cannot associate contents with a manifest hash")
	}
	hash := ir.Hash.String()

	records := ir.IndexRecords()
	if len(records) == 0 {
		zlog.Warn(ctx).Msg("manifest being indexed has 0 index records")
		return nil
	}

	// obtain a transaction scoped batch
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: indexManifest failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertManifestIndexQuery := newQuery(ctx, "indexer", "insert_manifest_index")
	queryStmt, err := tx.Prepare(ctx, "queryStmt", insertManifestIndexQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	defer insertManifestIndexQuery.Start(&err)()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, record := range records {
		// ignore nil packages
		if record.Package == nil {
			continue
		}

		v, err := toValues(*record)
		if err != nil {
			return fmt.Errorf("received a record with an invalid id: %v", err)
		}

		// if source package exists create record
		if v[0] != nil {
			err = mBatcher.Queue(
				ctx,
				queryStmt.SQL,
				v[0],
				v[2],
				v[3],
				hash,
			)
			if err != nil {
				return fmt.Errorf("batch insert failed for source package record %v: %w", record, err)
			}
		}

		err = mBatcher.Queue(
			ctx,
			queryStmt.SQL,
			v[1],
			v[2],
			v[3],
			hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package record %v: %w", record, err)
		}

	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

// toValues is a helper method which checks for
// nil pointers inside an IndexRecord before
// returning an associated pointer to the artifact
// in question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) ([4]*uint64, error) {
	res := [4]*uint64{}

	if r.Package.Source != nil {
		id, err := strconv.ParseUint(r.Package.Source.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("source package id %v: %v", r.Package.ID, err)
		}
		res[0] = &id
	}

	if r.Package != nil {
		id, err := strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %v", r.Package.ID, err)
		}
		res[1] = &id

	}

	if r.Distribution != nil {
		id, err := strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %v", r.Distribution.ID, err)
		}
		res[2] = &id
	}

	if r.Repository != nil {
		id, err := strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			// return res, fmt.Errorf("repository id %v: %v", r.Package.ID, err)
			return res, nil
		}
		res[3] = &id
	}

	return res, nil
}

// AffectedManifests finds the manifests digests which are affected by the provided vulnerability.
//
// An exhaustive search for all indexed packages of the same name as the vulnerability is performed.
//
// The list of packages is filtered down to only the affected set.
//
// The manifest index is then queried to resolve a list of manifest hashes containing the affected
// artifacts.
func (s *IndexerStore) AffectedManifests(ctx context.Context, v claircore.Vulnerability, vulnFunc claircore.CheckVulnernableFunc) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/affectedManifests")

	// confirm the incoming vuln can be
	// resolved into a prototype index record
	pr, err := protoRecord(ctx, s.pool, v)
	switch {
	case err == nil:
		// break out
	case errors.Is(err, ErrNotIndexed):
		// This is a common case: the system knows of a vulnerability but
		// doesn't know of any manifests it could apply to.
		return nil, nil
	default:
		return nil, err
	}

	// collect all packages which may be affected
	// by the vulnerability in question.
	pkgsToFilter := []claircore.Package{}

	selectPackages := newQuery(ctx, "indexer", "select_packages")
	end := selectPackages.Start(&err)
	rows, err := s.pool.Query(ctx, selectPackages.SQL, v.Package.Name)
	end()
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return []claircore.Digest{}, nil
	default:
		return nil, fmt.Errorf("failed to query packages associated with vulnerability %q: %w", v.ID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var pkg claircore.Package
		var id int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Version,
			&pkg.Kind,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package: %w", err)
		}
		idStr := strconv.FormatInt(id, 10)
		pkg.ID = idStr
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
		pkgsToFilter = append(pkgsToFilter, pkg)
	}
	zlog.Debug(ctx).Int("count", len(pkgsToFilter)).Msg("packages to filter")
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error scanning packages: %w", err)
	}

	// for each package discovered create an index record
	// and determine if any in-tree matcher finds the record vulnerable
	var filteredRecords []claircore.IndexRecord
	for _, pkg := range pkgsToFilter {
		pr.Package = &pkg
		match, err := vulnFunc(ctx, &pr, &v)
		if err != nil {
			return nil, err
		}
		if match {
			p := pkg // make a copy, or else you'll get a stale reference later
			filteredRecords = append(filteredRecords, claircore.IndexRecord{
				Package:      &p,
				Distribution: pr.Distribution,
				Repository:   pr.Repository,
			})
		}
	}
	zlog.Debug(ctx).Int("count", len(filteredRecords)).Msg("vulnerable index records")

	selectAffected := newQuery(ctx, "indexer", "select_affected")
	// Query the manifest index for manifests containing the vulnerable
	// IndexRecords and create a set containing each unique manifest.
	set := map[string]struct{}{}
	out := []claircore.Digest{}
	for _, record := range filteredRecords {
		v, err := toValues(record)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve record %+v to sql values for query: %w", record, err)
		}

		err = func() error {
			end := selectAffected.Start(&err)
			rows, err := s.pool.Query(ctx,
				selectAffected.SQL,
				record.Package.ID,
				v[2],
				v[3],
			)
			end()
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, pgx.ErrNoRows):
				err = fmt.Errorf("failed to query the manifest index: %w", err)
				fallthrough
			default:
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var hash claircore.Digest
				err := rows.Scan(&hash)
				if err != nil {
					return fmt.Errorf("failed scanning manifest hash into digest: %w", err)
				}
				if _, ok := set[hash.String()]; !ok {
					set[hash.String()] = struct{}{}
					out = append(out, hash)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return nil, err
		}
	}
	zlog.Debug(ctx).Int("count", len(out)).Msg("affected manifests")
	return out, nil
}

// protoRecord is a helper method which resolves a Vulnerability to an IndexRecord with no Package defined.
//
// it is an error for both a distribution and a repo to be missing from the Vulnerability.
func protoRecord(ctx context.Context, pool *pgxpool.Pool, v claircore.Vulnerability) (claircore.IndexRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/protoRecord")

	protoRecord := claircore.IndexRecord{}
	var err error
	selectDist := newQuery(ctx, "indexer", "select_distribution")
	// fill dist into prototype index record if exists
	if (v.Dist != nil) && (v.Dist.Name != "") {
		end := selectDist.Start(&err)
		row := pool.QueryRow(ctx,
			selectDist.SQL,
			v.Dist.Arch,
			v.Dist.CPE,
			v.Dist.DID,
			v.Dist.Name,
			v.Dist.PrettyName,
			v.Dist.Version,
			v.Dist.VersionCodeName,
			v.Dist.VersionID,
		)
		end()
		var id pgtype.Int8
		err := row.Scan(&id)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return protoRecord, fmt.Errorf("failed to scan dist: %w", err)
			}
		}

		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Distribution = &claircore.Distribution{
				ID:              id,
				Arch:            v.Dist.Arch,
				CPE:             v.Dist.CPE,
				DID:             v.Dist.DID,
				Name:            v.Dist.Name,
				PrettyName:      v.Dist.PrettyName,
				Version:         v.Dist.Version,
				VersionCodeName: v.Dist.VersionCodeName,
				VersionID:       v.Dist.VersionID,
			}
			zlog.Debug(ctx).Str("id", id).Msg("discovered distribution id")
		}
	}

	// fill repo into prototype index record if exists
	if (v.Repo != nil) && (v.Repo.Name != "") {
		selectRepo := newQuery(ctx, "indexer", "select_repository")
		defer selectRepo.Start(&err)()
		row := pool.QueryRow(ctx, selectRepo.SQL,
			v.Repo.Name,
			v.Repo.Key,
			v.Repo.URI,
		)
		var id pgtype.Int8
		err := row.Scan(&id)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return protoRecord, fmt.Errorf("failed to scan repo: %w", err)
			}
		}

		if id.Status == pgtype.Present {
			id := strconv.FormatInt(id.Int, 10)
			protoRecord.Repository = &claircore.Repository{
				ID:   id,
				Key:  v.Repo.Key,
				Name: v.Repo.Name,
				URI:  v.Repo.URI,
			}
			zlog.Debug(ctx).Str("id", id).Msg("discovered repo id")
		}
	}

	// we need at least a repo or distribution to continue
	if (protoRecord.Distribution == nil) && (protoRecord.Repository == nil) {
		return protoRecord, ErrNotIndexed
	}

	return protoRecord, nil
}

func (s *IndexerStore) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/DeleteManifests")
	rm, err := s.deleteManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	return rm, s.layerCleanup(ctx)
}

func (s *IndexerStore) deleteManifests(ctx context.Context, d []claircore.Digest) ([]claircore.Digest, error) {
	var err error
	deleteManifest := newQuery(ctx, "indexer", "delete_manifest")
	defer deleteManifest.Start(&err)()
	rows, err := s.pool.Query(ctx, deleteManifest.SQL, digestSlice(d))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rm := make([]claircore.Digest, 0, len(d)) // May over-allocate, but at least it's only doing it once.
	for rows.Next() {
		i := len(rm)
		rm = rm[:i+1]
		err = rows.Scan(&rm[i])
		if err != nil {
			return nil, err
		}
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("count", len(rm)).
		Int("nonexistant", len(d)-len(rm)).
		Msg("deleted manifests")
	return rm, nil
}

func (s *IndexerStore) layerCleanup(ctx context.Context) (err error) {
	deleteLayers := newQuery(ctx, "indexer", "delete_layers")
	defer deleteLayers.Start(&err)()
	tag, err := s.pool.Exec(ctx, deleteLayers.SQL)
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Int64("count", tag.RowsAffected()).
		Msg("deleted layers")
	return nil
}

func (s *IndexerStore) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	var err error
	selectScanner := newQuery(ctx, "indexer", "select_scanner")
	for i, scnr := range scnrs {
		end := selectScanner.Start(&err)
		err = s.pool.QueryRow(ctx, selectScanner.SQL, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		end()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve distribution ids for scanner %q: %w", scnr, err)
		}
	}

	query := newQuery(ctx, "indexer", "select_distributions_by_layer")
	defer query.Start(&err)()
	rows, err := s.pool.Query(ctx, query.SQL, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:distributionsByLayer no distribution found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:distributionsByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	defer rows.Close()

	res := []*claircore.Distribution{}
	for rows.Next() {
		var dist claircore.Distribution

		var id int64
		err := rows.Scan(
			&id,
			&dist.Name,
			&dist.DID,
			&dist.Version,
			&dist.VersionCodeName,
			&dist.VersionID,
			&dist.Arch,
			&dist.CPE,
			&dist.PrettyName,
		)
		dist.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution: %w", err)
		}

		res = append(res, &dist)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	// obtain a transaction scoped batch
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	insertQuery := newQuery(ctx, "indexer", "insert_distribution")
	insertDistStmt, err := tx.Prepare(ctx, "insertDistStmt", insertQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	end := insertQuery.Start(&err)
	defer end()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist: %w", err)
	}
	end()

	// make dist scan artifacts
	insertWithQuery := newQuery(ctx, "indexer", "insert_distribution_scanartifact")
	insertDistScanArtifactWithStmt, err := tx.Prepare(ctx, "insertDistScanArtifactWith", insertWithQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}
	defer insertWithQuery.Start(&err)()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, dist := range dists {
		err := mBatcher.Queue(
			ctx,
			insertDistScanArtifactWithStmt.SQL,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for dist_scanartifact %v: %w", dist, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for dist_scanartifact: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("store:indexDistributions failed to commit tx: %w", err)
	}
	return nil
}

// IndexPackages indexes all provided packages along with creating a scan artifact.
//
// If a source package is nested inside a binary package we index the source
// package first and then create a relation between the binary package and
// source package.
//
// Scan artifacts are used to determine if a particular layer has been scanned by a
// particular scanner. See the LayerScanned method for more details.
func (s *IndexerStore) IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/indexPackages")
	// obtain a transaction scoped batch
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackage failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertQuery := newQuery(ctx, "indexer", "insert_package")
	insertPackageStmt, err := tx.Prepare(ctx, "insertPackageStmt", insertQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	skipCt := 0

	end := insertQuery.Start(&err)
	defer end()
	zeroPackage := claircore.Package{}
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
		}
		if pkg.Source == nil {
			pkg.Source = &zeroPackage
		}

		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg.Source); err != nil {
			return err
		}
		if err := queueInsert(ctx, mBatcher, insertPackageStmt.Name, pkg); err != nil {
			return err
		}
	}
	err = mBatcher.Done(ctx)
	end()
	if err != nil {
		return fmt.Errorf("final batch insert failed for pkg: %w", err)
	}

	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("packages inserted")

	skipCt = 0
	// make package scan artifacts
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)

	insertWithQuery := newQuery(ctx, "indexer", "insert_package_scanartifact")
	insertPackageScanArtifactWithStmt, err := tx.Prepare(ctx, "insertPackageScanArtifactWith", insertWithQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create statement: %w", err)
	}

	defer insertWithQuery.Start(&err)()
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			skipCt++
			continue
		}
		err := mBatcher.Queue(
			ctx,
			insertPackageScanArtifactWithStmt.SQL,
			pkg.Source.Name,
			pkg.Source.Kind,
			pkg.Source.Version,
			pkg.Source.Module,
			pkg.Source.Arch,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			pkg.Module,
			pkg.Arch,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			layer.Hash,
			pkg.PackageDB,
			pkg.RepositoryHint,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for package_scanartifact %v: %w", pkg, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for package_scanartifact: %w", err)
	}
	zlog.Debug(ctx).
		Int("skipped", skipCt).
		Int("inserted", len(pkgs)-skipCt).
		Msg("scanartifacts inserted")

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("store:indexPackages failed to commit tx: %w", err)
	}
	return nil
}

func queueInsert(ctx context.Context, b *microbatch.Insert, stmt string, pkg *claircore.Package) error {
	var vKind *string
	var vNorm []int32
	if pkg.NormalizedVersion.Kind != "" {
		vKind = &pkg.NormalizedVersion.Kind
		vNorm = pkg.NormalizedVersion.V[:]
	}
	err := b.Queue(ctx, stmt,
		pkg.Name, pkg.Kind, pkg.Version, vKind, vNorm, pkg.Module, pkg.Arch,
	)
	if err != nil {
		return fmt.Errorf("failed to queue insert for package %q: %w", pkg.Name, err)
	}
	return nil
}

func (s *IndexerStore) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	// we scan into a jsonbIndexReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbIndexReport
	var err error
	insertReportQuery := newQuery(ctx, "indexer", "select_index_report")
	defer insertReportQuery.Start(&err)()
	err = s.pool.QueryRow(ctx, insertReportQuery.SQL, hash).Scan(&jsr)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("failed to retrieve index report: %w", err)
	}

	sr := claircore.IndexReport(jsr)
	return &sr, true, nil
}

func (s *IndexerStore) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, scnr indexer.VersionedScanner) error {
	// obtain a transaction scoped batch
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertRepoQuery := newQuery(ctx, "indexer", "insert_repository")
	insertRepoStmt, err := tx.Prepare(ctx, "insertRepoStmt", insertRepoQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create insert repo statement: %w", err)
	}

	end := insertRepoQuery.Start(&err)
	defer end()
	mBatcher := microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			repo.CPE,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	end()
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo: %w", err)
	}
	// make repo scan artifacts
	insertRepoScanartifactQuery := newQuery(ctx, "indexer", "insert_repository_scanartifact")
	insertRepoScanArtifactWithStmt, err := tx.Prepare(ctx, "insertRepoScanArtifactWith", insertRepoScanartifactQuery.SQL)
	if err != nil {
		return fmt.Errorf("failed to create insert repo scanartifact statement: %w", err)
	}
	defer insertRepoScanartifactQuery.Start(&err)()
	mBatcher = microbatch.NewInsert(tx, 500, time.Minute)
	for _, repo := range repos {
		err := mBatcher.Queue(
			ctx,
			insertRepoScanArtifactWithStmt.SQL,
			repo.Name,
			repo.Key,
			repo.URI,
			scnr.Name(),
			scnr.Version(),
			scnr.Kind(),
			l.Hash,
		)
		if err != nil {
			return fmt.Errorf("batch insert failed for repo_scanartifact %v: %w", repo, err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("final batch insert failed for repo_scanartifact: %w", err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("store:indexRepositories failed to commit tx: %w", err)
	}
	return nil
}

func (s *IndexerStore) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	var (
		scannerID int64
		err       error
	)
	selectScanner := newQuery(ctx, "indexer", "select_scanner")
	end := selectScanner.Start(&err)
	err = s.pool.QueryRow(ctx, selectScanner.SQL, scnr.Name(), scnr.Version(), scnr.Kind()).
		Scan(&scannerID)
	end()
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("scanner %s not found", scnr.Name())
	default:
		return false, err
	}

	var ok bool
	selectScanned := newQuery(ctx, "indexer", "select_layer_scanned")
	defer selectScanned.Start(&err)()
	err = s.pool.QueryRow(ctx, selectScanned.SQL, hash.String(), scannerID).
		Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// ManifestScanned determines if a manifest has been scanned by ALL the provided
// scanners.
func (s *IndexerStore) ManifestScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (bool, error) {
	// get the ids of the scanners we are testing for.
	expectedIDs, err := s.selectScanners(ctx, vs)
	if err != nil {
		return false, err
	}

	// get a map of the found ids which have scanned this package
	foundIDs := map[int64]struct{}{}

	selectScanned := newQuery(ctx, "indexer", "select_manifest_scanned")
	defer selectScanned.Start(&err)()
	rows, err := s.pool.Query(ctx, selectScanned.SQL, hash)
	if err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}
	defer rows.Close()
	var id int64
	for rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
		}
		foundIDs[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed to select scanner IDs for manifest: %w", err)
	}

	// compare the expectedIDs array with our foundIDs. if we get a lookup
	// miss we can say the manifest has not been scanned by all the layers provided
	for _, id := range expectedIDs {
		if _, ok := foundIDs[id]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func (s *IndexerStore) PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Package, error) {
	if len(scnrs) == 0 {
		return []*claircore.Package{}, nil
	}
	var err error
	selectScanner := newQuery(ctx, "indexer", "select_scanner")

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		end := selectScanner.Start(&err)
		err := s.pool.QueryRow(ctx, selectScanner.SQL, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve scanner ids: %w", err)
		}
		end()
	}

	selectPackagesByLayer := newQuery(ctx, "indexer", "select_packages_by_layer")
	defer selectPackagesByLayer.Start(&err)()
	rows, err := s.pool.Query(ctx, selectPackagesByLayer.SQL, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:packagesByLayer no packages found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:packagesByLayer failed to retrieve package rows for hash %v and scanners %v: %w", hash, scnrs, err)
	}
	defer rows.Close()

	res := []*claircore.Package{}
	for rows.Next() {
		var pkg claircore.Package
		var spkg claircore.Package

		var id, srcID int64
		var nKind *string
		var nVer pgtype.Int4Array
		err := rows.Scan(
			&id,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,
			&nKind,
			&nVer,
			&pkg.Module,
			&pkg.Arch,

			&srcID,
			&spkg.Name,
			&spkg.Kind,
			&spkg.Version,
			&spkg.Module,
			&spkg.Arch,

			&pkg.PackageDB,
			&pkg.RepositoryHint,
		)
		pkg.ID = strconv.FormatInt(id, 10)
		spkg.ID = strconv.FormatInt(srcID, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan packages: %w", err)
		}
		if nKind != nil {
			pkg.NormalizedVersion.Kind = *nKind
			for i, n := range nVer.Elements {
				pkg.NormalizedVersion.V[i] = n.Int
			}
		}
		// nest source package
		pkg.Source = &spkg

		res = append(res, &pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) PersistManifest(ctx context.Context, manifest claircore.Manifest) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertManifestQuery := newQuery(ctx, "indexer", "insert_manifest")
	end := insertManifestQuery.Start(&err)
	_, err = tx.Exec(ctx, insertManifestQuery.SQL, manifest.Hash)
	end()
	if err != nil {
		return fmt.Errorf("failed to insert manifest: %w", err)
	}

	insertLayerQuery := newQuery(ctx, "indexer", "insert_layer")
	insertManifestLayerQuery := newQuery(ctx, "indexer", "insert_manifest_layer")

	for i, layer := range manifest.Layers {
		end := insertLayerQuery.Start(&err)
		_, err = tx.Exec(ctx, insertLayerQuery.SQL, layer.Hash)
		if err != nil {
			return fmt.Errorf("failed to insert layer: %w", err)
		}
		end()

		end = insertManifestLayerQuery.Start(&err)
		_, err = tx.Exec(ctx, insertManifestLayerQuery.SQL, manifest.Hash, layer.Hash, i)
		end()
		if err != nil {
			return fmt.Errorf("failed to insert manifest -> layer link: %w", err)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

func (s *IndexerStore) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	var (
		ok  bool
		err error
	)
	scannerExistsQuery := newQuery(ctx, "indexer", "scanner_exists")
	scannerInsertQuery := newQuery(ctx, "indexer", "insert_scanner")

	for _, v := range vs {
		end := scannerExistsQuery.Start(&err)
		err = s.pool.QueryRow(ctx, scannerExistsQuery.SQL, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		end()
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %w", v.Name(), err)
		}
		if ok {
			continue
		}

		end = scannerInsertQuery.Start(&err)
		_, err = s.pool.Exec(ctx, scannerInsertQuery.SQL, v.Name(), v.Version(), v.Kind())
		end()
		if err != nil {
			return fmt.Errorf("failed to insert scanner %q: %w", v.Name(), err)
		}
	}

	return nil
}

func (s *IndexerStore) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	if len(scnrs) == 0 {
		return []*claircore.Repository{}, nil
	}
	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return nil, fmt.Errorf("unable to select scanners: %w", err)
	}

	selectReposQuery := newQuery(ctx, "indexer", "select_repositories_by_layer")
	defer selectReposQuery.Start(&err)()
	rows, err := s.pool.Query(ctx, selectReposQuery.SQL, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("no repositories found for layer, scanners set")
	default:
		return nil, fmt.Errorf("failed to retrieve repositories for layer, scanners set: %w", err)
	}
	defer rows.Close()

	res := []*claircore.Repository{}
	for rows.Next() {
		var repo claircore.Repository

		var id int64
		err := rows.Scan(
			&id,
			&repo.Name,
			&repo.Key,
			&repo.URI,
			&repo.CPE,
		)
		repo.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to scan repositories: %w", err)
		}

		res = append(res, &repo)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *IndexerStore) SetIndexFinished(ctx context.Context, ir *claircore.IndexReport, scnrs indexer.VersionedScanners) error {
	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return fmt.Errorf("failed to select package scanner id: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	insertManifestScannedQuery := newQuery(ctx, "indexer", "insert_manifest_scanned")

	// link extracted scanner IDs with incoming manifest
	for _, id := range scannerIDs {
		end := insertManifestScannedQuery.Start(&err)
		_, err := tx.Exec(ctx, insertManifestScannedQuery.SQL, ir.Hash, id)
		end()
		if err != nil {
			return fmt.Errorf("failed to link manifest with scanner list: %w", err)
		}
	}

	// push IndexReport to the store
	// we cast claircore.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations

	upsertIndexReportQuery := newQuery(ctx, "indexer", "upsert_index_report")
	defer upsertIndexReportQuery.Start(&err)()
	_, err = tx.Exec(ctx, upsertIndexReportQuery.SQL, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert scan result: %w", err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *IndexerStore) SetIndexReport(ctx context.Context, ir *claircore.IndexReport) error {
	// we cast scanner.IndexReport to jsonbIndexReport in order to obtain the value/scan
	// implementations
	var err error
	upsertIndexReportQuery := newQuery(ctx, "indexer", "upsert_index_report")
	defer upsertIndexReportQuery.Start(&err)()
	_, err = s.pool.Exec(ctx, upsertIndexReportQuery.SQL, ir.Hash, jsonbIndexReport(*ir))
	if err != nil {
		return fmt.Errorf("failed to upsert index report: %w", err)
	}
	return nil
}

func (s *IndexerStore) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx, "scanner", vs.Name())
	var err error
	setLayerScannedQuery := newQuery(ctx, "indexer", "set_layer_scanned")
	defer setLayerScannedQuery.Start(&err)()
	_, err = s.pool.Exec(ctx, setLayerScannedQuery.SQL, hash, vs.Name(), vs.Version(), vs.Kind())
	if err != nil {
		return fmt.Errorf("error setting layer scanned: %w", err)
	}

	return nil
}
