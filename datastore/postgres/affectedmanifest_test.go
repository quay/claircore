package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/types/cpe"
)

type affectedTest struct {
	store        indexer.Store
	pool         *pgxpool.Pool
	ctx          context.Context
	ir           claircore.IndexReport
	v            *claircore.Vulnerability
	isVulnerable bool
}

func (e *affectedTest) Run(t *testing.T) {
	type subtest struct {
		name string
		do   func(t *testing.T)
	}
	subtests := [...]subtest{
		{"IndexArtifacts", e.IndexArtifacts},
		{"IndexManifest", e.IndexManifest},
		{"AffectedManifests", e.AffectedManifests},
	}
	for _, subtest := range subtests {
		if !t.Run(subtest.name, subtest.do) {
			t.FailNow()
		}
	}
}

// IndexArtifacts manually writes all the necessary
// artifacts to the db.
//
// this is required so foreign key constraints do not
// fail in later tests.
func (e *affectedTest) IndexArtifacts(t *testing.T) {
	ctx := zlog.Test(e.ctx, t)
	const (
		insertManifest = `
		INSERT INTO	manifest
			(hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertPkg = `
		INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch, id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT DO NOTHING;
		`
		insertDist = `
		INSERT INTO dist
			(name, did, version, version_code_name, version_id, arch, cpe, pretty_name, id)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING;
		`
		insertRepo = `
		INSERT INTO repo
			(name, key, uri, id, cpe)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING;
		`
	)
	_, err := e.pool.Exec(ctx, insertManifest, e.ir.Hash.String())
	if err != nil {
		t.Fatalf("failed to insert manifest: %v", err)
	}
	for _, pkg := range e.ir.Packages {
		var nVer pgtype.Int4Array
		nVer.Status = pgtype.Present
		nVer.Set(pkg.NormalizedVersion.V)
		_, err := e.pool.Exec(ctx, insertPkg,
			pkg.Name,
			pkg.Kind,
			pkg.Version,
			pkg.NormalizedVersion.Kind,
			&nVer,
			pkg.Module,
			pkg.Arch,
			pkg.ID,
		)
		if err != nil {
			t.Fatalf("failed to insert package: %v", err)
		}
		if pkg.Source != nil {
			pkg := pkg.Source
			nVer.Set(pkg.NormalizedVersion.V)
			_, err := e.pool.Exec(ctx, insertPkg,
				pkg.Name,
				pkg.Kind,
				pkg.Version,
				pkg.NormalizedVersion.Kind,
				&nVer,
				pkg.Module,
				pkg.Arch,
				pkg.ID,
			)
			if err != nil {
				t.Fatalf("failed to insert source package: %v", err)
			}
		}
	}
	for _, dist := range e.ir.Distributions {
		_, err := e.pool.Exec(ctx, insertDist,
			dist.Name,
			dist.DID,
			dist.Version,
			dist.VersionCodeName,
			dist.VersionID,
			dist.Arch,
			dist.CPE,
			dist.PrettyName,
			dist.ID,
		)
		if err != nil {
			t.Fatalf("failed to insert dist: %v", err)
		}
	}
	for _, repo := range e.ir.Repositories {
		_, err := e.pool.Exec(ctx, insertRepo,
			repo.Name,
			repo.Key,
			repo.URI,
			repo.ID,
			repo.CPE,
		)
		if err != nil {
			t.Fatalf("failed to insert repo: %v", err)
		}
	}
}

// IndexManifest confirms the contents of a manifest
// can be written to the manifest index table.
func (e *affectedTest) IndexManifest(t *testing.T) {
	ctx := zlog.Test(e.ctx, t)
	err := e.store.IndexManifest(ctx, &e.ir)
	if err != nil {
		t.Fatalf("failed to index manifest: %v", err)
	}
}

// AffectedManifests confirms each vulnerability
// in the vulnereability report reports the associated
// manifest is affected.
func (e *affectedTest) AffectedManifests(t *testing.T) {
	ctx := zlog.Test(e.ctx, t)
	hashes, err := e.store.AffectedManifests(ctx, *e.v)
	if err != nil {
		t.Fatalf("failed to retrieve affected manifest for vuln %s: %v", e.v.ID, err)
	}

	if len(hashes) == 0 && e.isVulnerable {
		t.Fatalf("expected manifest to be vulnerable to %s for package %s", e.v.Name, e.v.Package.Name)
	}

	if len(hashes) == 1 && !e.isVulnerable {
		t.Fatalf("expected manifest not to be vulnerable to %s for package %s", e.v.Name, e.v.Package.Name)
	}
}

type afTestCase struct {
	name         string
	vuln         *claircore.Vulnerability
	isVulnerable bool
	indexReport  string
}

func TestAffectedManifests(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	integration.NeedDB(t)
	pool := pgtest.TestIndexerDB(ctx, t)
	store := NewIndexerStore(pool)

	testCases := []afTestCase{
		{
			name: "rhel_simple_affected",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "10.32-4.el8_6",
				Package: &claircore.Package{
					Name: "pcre2",
				},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  "rhel-cpe-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*"),
				},
			},
			isVulnerable: true,
			indexReport:  "rhacs-main-rhel8.index.json",
		},
		{
			name: "rhel_simple_not_affected_by_version",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "10.32-2.el8_6",
				Package: &claircore.Package{
					Name: "pcre2",
				},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  "rhel-cpe-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*"),
				},
			},
			isVulnerable: false,
			indexReport:  "rhacs-main-rhel8.index.json",
		},
		{
			name: "rhel_simple_not_affected_by_repo",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "10.32-2.el8_6",
				Package: &claircore.Package{
					Name: "pcre2",
				},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  "rhel-cpe-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:8:*:not_real:*:*:*:*:*"),
				},
			},
			isVulnerable: false,
			indexReport:  "rhacs-main-rhel8.index.json",
		},
		{
			name: "go_simple_affected_by_version",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "v1.4.3",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("v0.0.1")),
					Upper: claircore.FromSemver(semver.MustParse("v1.4.3")),
				},
				Package: &claircore.Package{
					Name: "github.com/go-errors/errors",
				},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{
					Name: "go",
					URI:  "https://pkg.go.dev/",
				},
			},
			isVulnerable: true,
			indexReport:  "rhacs-main-rhel8.index.json",
		},
		{
			name: "go_simple_not_affected_by_version",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "v1.4.1",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("v0.0.1")),
					Upper: claircore.FromSemver(semver.MustParse("v1.4.1")),
				},
				Package: &claircore.Package{
					Name: "github.com/go-errors/errors",
				},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{
					Name: "go",
					URI:  "https://pkg.go.dev/",
				},
			},
			isVulnerable: false,
			indexReport:  "rhacs-main-rhel8.index.json",
		},
		{
			name: "debian_simple_affected",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "1.9-3+deb10u2",
				Package: &claircore.Package{
					Name: "gzip",
				},
				Dist: &claircore.Distribution{
					DID:     "debian",
					Name:    "Debian GNU/Linux",
					Version: "10 (buster)",
				},
				Repo: &claircore.Repository{},
			},
			isVulnerable: true,
			indexReport:  "docker.io-library-debian-10.index.json",
		},
		{
			name: "debian_not_affected_bad_dist",
			vuln: &claircore.Vulnerability{
				Name:           "CVE-123",
				FixedInVersion: "1.9-3+deb10u2",
				Package: &claircore.Package{
					Name: "gzip",
				},
				Dist: &claircore.Distribution{
					DID:     "debian",
					Name:    "Debian GNU/Linux",
					Version: "9 (Stretch)",
				},
				Repo: &claircore.Repository{},
			},
			isVulnerable: false,
			indexReport:  "docker.io-library-debian-10.index.json",
		},
	}
	for _, tc := range testCases {
		irPath := filepath.Join("testdata", tc.indexReport)
		irFD, err := os.Open(irPath)
		if err != nil {
			t.Fatalf("fd open for ir failed: %v", err)
		}

		var ir claircore.IndexReport
		err = json.NewDecoder(irFD).Decode(&ir)
		if err != nil {
			t.Fatalf("could not decode ir: %v", err)
		}
		e2e := &affectedTest{
			store:        store,
			pool:         pool,
			ctx:          ctx,
			ir:           ir,
			v:            tc.vuln,
			isVulnerable: tc.isVulnerable,
		}
		t.Run(tc.name, e2e.Run)
	}
}
