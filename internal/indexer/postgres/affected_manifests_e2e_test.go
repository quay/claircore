package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test/integration"
)

type affectedE2E struct {
	store indexer.Store
	pool  *pgxpool.Pool
	ctx   context.Context
	ir    claircore.IndexReport
	vr    claircore.VulnerabilityReport
}

func TestAffectedE2E(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := TestDatabase(ctx, t)
	store := NewStore(pool)
	defer store.Close(ctx)

	table := []struct {
		// name of the defined affectedE2E test
		name string
		// file name of index report in ./testdata
		irFName string
		// file name of vuln report in ./testdata
		vrFName string
	}{
		// these fixtures
		// were generated against the same database
		// to ensure all ids are sequentially increasing
		//
		// if fixtures are added you must generate
		// this current set *and* your new fixtures against the same database
		// to ensure there are no ID overlaps
		{
			name:    "amazonlinux 1",
			irFName: "amazonlinux-1.index.json",
			vrFName: "amazonlinux-1.report.json",
		},
		{
			name:    "debian 8",
			irFName: "debian-8.index.json",
			vrFName: "debian-8.report.json",
		},
		{
			name:    "debian 9",
			irFName: "debian-9.index.json",
			vrFName: "debian-9.report.json",
		},
		{
			name:    "debian 10",
			irFName: "debian-10.index.json",
			vrFName: "debian-10.report.json",
		},
		{
			name:    "ubi 8",
			irFName: "ubi.index.json",
			vrFName: "ubi.report.json",
		},
		{
			name:    "ubuntu 16.04",
			irFName: "ubuntu-16.04.index.json",
			vrFName: "ubuntu-16.04.report.json",
		},
		{
			name:    "ubuntu 18.04",
			irFName: "ubuntu-18.04.index.json",
			vrFName: "ubuntu-18.04.report.json",
		},
		{
			name:    "ubuntu 19.10",
			irFName: "ubuntu-19.10.index.json",
			vrFName: "ubuntu-19.10.report.json",
		},
		{
			name:    "ubuntu 20.04",
			irFName: "ubuntu-20.04.index.json",
			vrFName: "ubuntu-20.04.report.json",
		},
		{
			name:    "mitmproxy 4.0.1",
			irFName: "mitmproxy-4.0.1.index.json",
			vrFName: "mitmproxy-4.0.1.report.json",
		},
	}

	for _, tt := range table {
		// grab and deserialize test data
		irPath := filepath.Join("testdata", tt.irFName)
		vrPath := filepath.Join("testdata", tt.vrFName)
		irFD, err := os.Open(irPath)
		if err != nil {
			t.Fatalf("fd open for ir failed: %v", err)
		}
		vrFD, err := os.Open(vrPath)
		if err != nil {
			t.Fatalf("fd open for vr failed: %v", err)
		}

		var ir claircore.IndexReport
		var vr claircore.VulnerabilityReport

		err = json.NewDecoder(irFD).Decode(&ir)
		if err != nil {
			t.Fatalf("could not decode ir: %v", err)
		}

		err = json.NewDecoder(vrFD).Decode(&vr)
		if err != nil {
			t.Fatalf("could not decode vr: %v", err)
		}

		// create and run e2e test
		e2e := &affectedE2E{
			store: store,
			pool:  pool,
			ctx:   ctx,
			ir:    ir,
			vr:    vr,
		}
		t.Run(tt.name, e2e.Run)
	}
}

func (e *affectedE2E) Run(t *testing.T) {
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
func (e *affectedE2E) IndexArtifacts(t *testing.T) {
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
			(name, key, uri, id)
		VALUES ($1, $2, $3, $4)
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
		)
		if err != nil {
			t.Fatalf("failed to insert repo: %v", err)
		}
	}
}

// IndexManifest confirms the contents of a manifest
// can be written to the manifest index table.
func (e *affectedE2E) IndexManifest(t *testing.T) {
	ctx := zlog.Test(e.ctx, t)
	err := e.store.IndexManifest(ctx, &e.ir)
	if err != nil {
		t.Fatalf("failed to index manifest: %v", err)
	}
}

// AffectedManifests confirms each vulnerability
// in the vulnereability report reports the associated
// manifest is affected.
func (e *affectedE2E) AffectedManifests(t *testing.T) {
	ctx := zlog.Test(e.ctx, t)
	for _, vuln := range e.vr.Vulnerabilities {
		hashes, err := e.store.AffectedManifests(ctx, *vuln)
		if err != nil {
			t.Fatalf("failed to retrieve affected manifest for vuln %s: %v", vuln.ID, err)
		}

		if len(hashes) != 1 {
			t.Fatalf("got: len(hashes)==%d, want: len(hashes)==1", len(hashes))
		}

		got := hashes[0].String()
		wanted := e.ir.Hash.String()
		if got != wanted {
			t.Fatalf("got: %v, want: %v", got, wanted)
		}
	}
}
