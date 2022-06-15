package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore/updater/driver/v1"
)

type Updater struct {
	pool *pgxpool.Pool
}

// ...
//
// The passed Context is only used during the call to NewUpdater.
//
// Close must be called or the program may panic.
func NewUpdater(ctx context.Context, db *MatcherDB) (*Updater, error) {
	u := &Updater{
		pool: (*pgxpool.Pool)(db),
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(u, func(u *Updater) {
		panic(fmt.Sprintf("%s:%d: Updater not closed", file, line))
	})
	return u, nil
}

func (u *Updater) Close() error {
	runtime.SetFinalizer(u, nil)
	u.pool = nil
	return nil
}

func (u *Updater) UpdateEnrichments(ctx context.Context, ref uuid.UUID, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) error {
	var (
		//go:embed queries/updater/create_enrichment_update.sql
		create string
		//go:embed queries/updater/insert_enrichments.sql
		insert string
	)
	ctx = zlog.ContextWithValues(ctx,
		"component", "database/postgres/Updater.UpdateEnrichments",
		"ref", ref.String())

	err := u.pool.BeginFunc(ctx, func(tx pgx.Tx) error {
		var id uint64
		err := tx.BeginFunc(ctx, func(tx pgx.Tx) (err error) {
			const name = `create`
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				updateEnrichmentsDuration.WithLabelValues(name, errLabel(err)).Observe(v)
			}))
			defer timer.ObserveDuration()
			err = tx.QueryRow(ctx, create, ref, kind, string(fp)).Scan(&id)
			updateEnrichmentsCounter.WithLabelValues(name, errLabel(err)).Add(1)
			if err != nil {
				return err
			}
			updateEnrichmentsAffected.WithLabelValues(name, errLabel(err)).Add(1)
			return nil
		})
		if err != nil {
			return err
		}
		zlog.Debug(ctx).
			Msg("update_operation created")

		for i := range es {
			err = func() error {
				const name = `insert`
				hashKind, hash := hashEnrichment(&es[i])
				timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
					updateEnrichmentsDuration.WithLabelValues(name, errLabel(err)).Observe(v)
				}))
				defer timer.ObserveDuration()
				tag, err := tx.Exec(ctx, insert,
					hashKind, hash, kind, es[i].Tags, es[i].Enrichment, id,
				)
				updateEnrichmentsCounter.WithLabelValues(name, errLabel(err)).Add(1)
				if err != nil {
					return err
				}
				updateEnrichmentsAffected.WithLabelValues(name, errLabel(err)).Add(float64(tag.RowsAffected()))
				return nil
			}()
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	zlog.Debug(ctx).
		Stringer("ref", ref).
		Int("inserted", len(es)).
		Msg("update_operation committed")
	return nil
}

func (u *Updater) UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs *driver.ParsedVulnerabilities) error {
	const (
		// Insert attempts to create a new vulnerability. It fails silently.
		insert = `
		INSERT INTO vuln (
			hash_kind, hash,
			name, updater, description, issued, links, severity, normalized_severity,
			package_name, package_version, package_module, package_arch, package_kind,
			dist_id, dist_name, dist_version, dist_version_code_name, dist_version_id, dist_arch, dist_cpe, dist_pretty_name,
			repo_name, repo_key, repo_uri,
			fixed_in_version, arch_operation, version_kind, vulnerable_range
		) VALUES (
		  $1, $2,
		  $3, $4, $5, $6, $7, $8, $9,
		  $10, $11, $12, $13, $14,
		  $15, $16, $17, $18, $19, $20, $21, $22,
		  $23, $24, $25,
		  $26, $27, $28, VersionRange($29, $30)
		)
		ON CONFLICT (hash_kind, hash) DO NOTHING;`
		// Assoc associates an update operation and a vulnerability. It fails
		// silently.
		assoc = `
		INSERT INTO uo_vuln (uo, vuln) VALUES (
			$3,
			(SELECT id FROM vuln WHERE hash_kind = $1 AND hash = $2))
		ON CONFLICT DO NOTHING;`
	)

	//go:embed queries/updater/create_vulnerability_update.sql
	var create string
	ctx = zlog.ContextWithValues(ctx,
		"component", "database/postgres/Updater.UpdateVulnerabilities",
		"ref", ref.String(),
	)

	err := u.pool.BeginFunc(ctx, func(tx pgx.Tx) error {
		var id uint64
		err := tx.BeginFunc(ctx, func(tx pgx.Tx) (err error) {
			const name = `create`
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				updateVulnerabilitiesDuration.WithLabelValues(name, errLabel(err)).Observe(v)
			}))
			defer timer.ObserveDuration()
			err = tx.QueryRow(ctx, create, ref, updater, string(fp)).Scan(&id)
			updateVulnerabilitiesCounter.WithLabelValues(name, errLabel(err)).Add(1)
			updateVulnerabilitiesAffected.WithLabelValues(name, errLabel(err)).Add(1)
			return err
		})
		if err != nil {
			return err
		}
		zlog.Debug(ctx).
			Msg("update_operation created")

		// Ideally, we'd use BeginFunc again, but that's a lot of SAVEPOINTs so
		// don't.
		eg, ctx := errgroup.WithContext(ctx)
		// Item is a vuln with the additional precomputaiton done.
		type item struct {
			Vulnerability vuln
			Hash          []byte
			HashKind      string
			RangeKind     string
			RangeLower    string
			RangeUpper    string
		}
		vulnCh := make(chan vuln)
		itemCh := make(chan item)
		eg.Go(func() error {
			defer close(vulnCh)
			for i, v := range vs.Vulnerability {
				// Template
				tv := vuln{
					Vulnerability: i,
					Package:       -1,
					Distribution:  v.Distribution,
					Repository:    v.Repository,
				}
				for _, p := range v.Package {
					// per-package
					pv := tv
					pv.Package = p
					select {
					case <-ctx.Done():
						return ctx.Err()
					case vulnCh <- pv:
					}
				}
			}
			return nil
		})
		eg.Go(func() error {
			defer close(itemCh)
			for v := range vulnCh {
				i := item{
					Vulnerability: v,
				}
				i.HashKind, i.Hash = v.Hash(vs)
				i.RangeKind, i.RangeLower, i.RangeUpper = rangefmt(vs.Vulnerability[v.Vulnerability].Range)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case itemCh <- i:
				}
			}
			return nil
		})
		eg.Go(func() error {
			const name = `create`
			var err error
			var tag pgconn.CommandTag
			for i := range itemCh {
				v := vs.Vulnerability[i.Vulnerability.Vulnerability]
				p := vs.Package[i.Vulnerability.Package]
				timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
					updateVulnerabilitiesDuration.WithLabelValues(name, errLabel(err)).Observe(v)
				}))
				tag, err = tx.Exec(ctx, insert,
					i.HashKind, i.Hash,
					v.Name, vs.Updater, v.Description, v.Issued, strings.Join(v.Links, " "), v.Severity.Upstream, v.Severity.Normalized.String(),
					p.Name, p.Version, p.Module, p.Arch, p.Kind.String(),
					"", "", "", "", "", "", "", "", // TODO
					"", "", "", // TODO
					v.FixedInVersion, v.ArchOperation, i.RangeKind, i.RangeLower, i.RangeUpper,
				)
				updateVulnerabilitiesCounter.WithLabelValues(name, errLabel(err)).Add(1)
				timer.ObserveDuration()
				if err != nil {
					return err
				}
				updateVulnerabilitiesAffected.WithLabelValues(name, errLabel(err)).Add(float64(tag.RowsAffected()))
			}
			return nil
		})
		return eg.Wait()
	})
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Msg("update_operation committed")
	return nil
}

func (u *Updater) GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error) {
	//go:embed queries/updater/get_update_operations.sql
	var getOperations string
	ctx = zlog.ContextWithValues(ctx, "component", "internal/vulnstore/postgres/getUpdateOperations")

	var (
		out []driver.UpdateOperation
		// These are reused on every call to the function below.
		ref     uuid.UUID
		updater string
		fp      string
		date    time.Time
		kind    string
	)
	_, err := u.pool.QueryFunc(ctx, getOperations, nil,
		[]interface{}{&ref, &updater, &fp, &date, &kind},
		func(_ pgx.QueryFuncRow) error {
			out = append(out, driver.UpdateOperation{
				Ref:         ref,
				Updater:     updater,
				Fingerprint: driver.Fingerprint(fp),
				Date:        date,
				Kind:        driver.UpdateKind(kind),
			})
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}
