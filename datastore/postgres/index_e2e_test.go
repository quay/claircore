package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

// mockScnr is a kind-agnostic scanner we will
// use for testing purposes.
type mockScnr struct {
	name    string
	kind    string
	version string
}

func (m mockScnr) Name() string {
	return m.name
}
func (m mockScnr) Kind() string {
	return m.kind
}
func (m mockScnr) Version() string {
	return m.version
}

type indexE2e struct {
	name       string
	store      indexer.Store
	ctx        context.Context
	manifest   claircore.Manifest
	scnrs      indexer.VersionedScanners
	packageGen int
	distGen    int
	repoGen    int
}

func TestIndexE2E(t *testing.T) {
	integration.NeedDB(t)
	ctx := context.Background()

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			pool := pgtest.TestIndexerDB(ctx, t)
			defer pool.Close()

			e := setupIndexE2E(ctx, pool, scenario, t)
			e.RunAll(t)
		})
	}
}

// RunAll executes all test steps in sequence
func (e *indexE2e) RunAll(t testing.TB) {
	steps := []struct {
		name string
		fn   func(testing.TB)
	}{
		{"RegisterScanner", e.RegisterScanner},
		{"PersistManifest", e.PersistManifest},
		{"IndexAndRetrievePackages", e.IndexAndRetrievePackages},
		{"IndexAndRetrieveDistributions", e.IndexAndRetrieveDistributions},
		{"IndexAndRetrieveRepos", e.IndexAndRetrieveRepos},
		{"LayerScanned", e.LayerScanned},
		{"LayerScannedNotExists", e.LayerScannedNotExists},
		{"LayerScannedFalse", e.LayerScannedFalse},
		{"IndexReport", e.IndexReport},
	}

	// For benchmarks, run steps directly without subtests to avoid conflicts
	if _, isBenchmark := t.(*testing.B); isBenchmark {
		for _, step := range steps {
			step.fn(t)
		}
		return
	}

	// For regular tests, use subtests
	for _, step := range steps {
		if tt, ok := t.(*testing.T); ok {
			if !tt.Run(step.name, func(t *testing.T) { step.fn(t) }) {
				tt.FailNow()
			}
		} else {
			// Fallback - just call the function directly
			step.fn(t)
		}
	}
}

// RegisterScanner confirms a scanner can be registered
// and provides this scanner for other subtests to use
func (e *indexE2e) RegisterScanner(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	err := e.store.RegisterScanners(ctx, e.scnrs)
	if err != nil {
		t.Fatalf("failed to register scnr: %v", err)
	}
}

// PersistManifest confirms that manifests and layers can be persisted
// to the database, creating the necessary records for subsequent operations.
func (e *indexE2e) PersistManifest(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	err := e.store.PersistManifest(ctx, e.manifest)
	if err != nil {
		t.Fatalf("failed to persist manifest: %v", err)
	}
}

// IndexAndRetrievePackages confirms inserting and
// selecting packages associated with a layer works
// correctly.
func (e *indexE2e) IndexAndRetrievePackages(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	A := test.GenUniquePackages(e.packageGen)

	for _, scnr := range e.scnrs {
		err := e.store.IndexPackages(ctx, A, e.manifest.Layers[0], scnr)
		if err != nil {
			t.Fatalf("failed to index package: %v", err)
		}
	}

	B, err := e.store.PackagesByLayer(ctx, e.manifest.Layers[0].Hash, e.scnrs)
	if err != nil {
		t.Fatalf("failed to retrieve packages by layer: %v", err)
	}

	if len(e.scnrs)*e.packageGen != len(B) {
		t.Fatalf("wanted len: %v got: %v", len(e.scnrs)*e.packageGen, len(B))
	}
}

// IndexAndRetrieveDistributions confirms inserting and
// selecting distributions associated with a layer works
// correctly.
func (e *indexE2e) IndexAndRetrieveDistributions(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	A := test.GenUniqueDistributions(e.distGen)

	for _, scnr := range e.scnrs {
		err := e.store.IndexDistributions(ctx, A, e.manifest.Layers[0], scnr)
		if err != nil {
			t.Fatalf("failed to index distributions: %v", err)
		}
	}

	B, err := e.store.DistributionsByLayer(ctx, e.manifest.Layers[0].Hash, e.scnrs)
	if err != nil {
		t.Fatalf("failed to retrieve distributions by layer: %v", err)
	}

	if len(e.scnrs)*e.distGen != len(B) {
		t.Fatalf("wanted len: %v got: %v", len(e.scnrs)*e.distGen, len(B))
	}
}

// IndexAndRetrieveRepos confirms inserting and
// selecting repositories associated with a layer works
// correctly.
func (e *indexE2e) IndexAndRetrieveRepos(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	A := test.GenUniqueRepositories(e.repoGen)

	for _, scnr := range e.scnrs {
		err := e.store.IndexRepositories(ctx, A, e.manifest.Layers[0], scnr)
		if err != nil {
			t.Fatalf("failed to index repos: %v", err)
		}
	}

	B, err := e.store.RepositoriesByLayer(ctx, e.manifest.Layers[0].Hash, e.scnrs)
	if err != nil {
		t.Fatalf("failed to retrieve repos by layer: %v", err)
	}

	if len(e.scnrs)*e.repoGen != len(B) {
		t.Fatalf("wanted len: %v got: %v", len(e.scnrs)*e.repoGen, len(B))
	}
}

// LayerScanned confirms the book keeping involved in marking a layer
// scanned works correctly.
func (e *indexE2e) LayerScanned(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	for _, scnr := range e.scnrs {
		err := e.store.SetLayerScanned(ctx, e.manifest.Layers[0].Hash, scnr)
		if err != nil {
			t.Fatalf("failed to set layer scanned: %v", err)
		}

		b, err := e.store.LayerScanned(ctx, e.manifest.Layers[0].Hash, scnr)
		if err != nil {
			t.Fatalf("failed to query if layer is scanned: %v", err)
		}
		if !b {
			t.Fatalf("expected layer to be scanned")
		}
	}
}

// LayerScannedNotExists confirms an error is returned when attempting
// to obtain if a layer was scanned by a non-existent scanner.
func (e *indexE2e) LayerScannedNotExists(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)
	scnr := mockScnr{
		name:    "invalid",
		kind:    "invalid",
		version: "invalid",
	}

	_, err := e.store.LayerScanned(ctx, e.manifest.Layers[0].Hash, scnr)
	if err == nil {
		t.Fatalf("expected error scnr not found error condition")
	}
}

// LayerScannedFalse confirms a false boolean is returned when attempting
// to obtain if a non-exitent layer was scanned by a valid scanner
func (e *indexE2e) LayerScannedFalse(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)

	// create a layer that has not been persisted to the store
	layer := &claircore.Layer{
		Hash: claircore.MustParseDigest(`sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03`),
	}

	b, err := e.store.LayerScanned(ctx, layer.Hash, e.scnrs[0])
	if err != nil {
		t.Fatalf("failed to query if layer is scanned: %v", err)
	}
	if b {
		t.Fatalf("expected layer not to be scanned")
	}
}

// IndexReport confirms the book keeping around index reports works
// correctly.
func (e *indexE2e) IndexReport(t testing.TB) {
	ctx := zlog.Test(e.ctx, t)

	A := &claircore.IndexReport{
		Hash:  e.manifest.Hash,
		State: "Testing",
	}

	err := e.store.SetIndexReport(ctx, A)
	if err != nil {
		t.Fatalf("failed to set index report: %v", err)
	}
	B, ok, err := e.store.IndexReport(ctx, e.manifest.Hash)
	if err != nil {
		t.Fatalf("failed to retrieve index report: %v", err)
	}
	if !ok {
		t.Fatalf("no index report found")
	}
	if !cmp.Equal(A.Hash.String(), B.Hash.String()) {
		t.Fatalf("%v", cmp.Diff(A.Hash.String(), B.Hash.String()))
	}
	if !cmp.Equal(A.State, B.State) {
		t.Fatalf("%v", cmp.Diff(A.Hash.String(), B.Hash.String()))
	}

	A.State = "IndexFinished"
	err = e.store.SetIndexFinished(ctx, A, e.scnrs)
	if err != nil {
		t.Fatalf("failed to set index as finished: %v", err)
	}

	b, err := e.store.ManifestScanned(ctx, e.manifest.Hash, e.scnrs)
	if err != nil {
		t.Fatalf("failed to query if manifest was scanned: %v", err)
	}
	if !b {
		t.Fatalf("expected manifest to be scanned")
	}

	B, ok, err = e.store.IndexReport(ctx, e.manifest.Hash)
	if err != nil {
		t.Fatalf("failed to retrieve index report: %v", err)
	}
	if !ok {
		t.Fatalf("no index report found")
	}
	if !cmp.Equal(A.Hash.String(), B.Hash.String()) {
		t.Fatalf("%v", cmp.Diff(A.Hash.String(), B.Hash.String()))
	}
	if !cmp.Equal(A.State, B.State) {
		t.Fatalf("%v", cmp.Diff(A.Hash.String(), B.Hash.String()))
	}
}

func BenchmarkIndexE2E(b *testing.B) {
	integration.NeedDB(b)
	ctx := context.Background()

	for _, scenario := range testScenarios {
		b.Run(scenario.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				pool := pgtest.TestIndexerDB(ctx, b)
				e := setupIndexE2E(ctx, pool, scenario, b)
				b.StartTimer()

				e.RunAll(b)

				b.StopTimer()
				pool.Close()
				b.StartTimer()
			}
		})
	}
}

// testScenarios defines shared test scenarios for both tests and benchmarks
var testScenarios = []indexE2e{
	{
		name: "3_scanners_small",
		scnrs: indexer.VersionedScanners{
			mockScnr{name: "test-scanner", kind: "test", version: "v0.0.1"},
			mockScnr{name: "test-scanner1", kind: "test", version: "v0.0.11"},
			mockScnr{name: "test-scanner2", kind: "test", version: "v0.0.8"},
		},
		packageGen: 100,
		distGen:    150,
		repoGen:    50,
	},
	{
		name: "6_scanners_small",
		scnrs: indexer.VersionedScanners{
			mockScnr{name: "test-scanner", kind: "test", version: "v0.0.1"},
			mockScnr{name: "test-scanner1", kind: "test", version: "v0.0.11"},
			mockScnr{name: "test-scanner2", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner3", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner4", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner5", kind: "test", version: "v0.0.8"},
		},
		packageGen: 100,
		distGen:    150,
		repoGen:    50,
	},
	{
		name: "3_scanners_large",
		scnrs: indexer.VersionedScanners{
			mockScnr{name: "test-scanner", kind: "test", version: "v0.0.1"},
			mockScnr{name: "test-scanner1", kind: "test", version: "v0.0.11"},
			mockScnr{name: "test-scanner2", kind: "test", version: "v0.0.8"},
		},
		packageGen: 1000,
		distGen:    1500,
		repoGen:    500,
	},
	{
		name: "6_scanners_large",
		scnrs: indexer.VersionedScanners{
			mockScnr{name: "test-scanner", kind: "test", version: "v0.0.1"},
			mockScnr{name: "test-scanner1", kind: "test", version: "v0.0.11"},
			mockScnr{name: "test-scanner2", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner3", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner4", kind: "test", version: "v0.0.8"},
			mockScnr{name: "test-scanner5", kind: "test", version: "v0.0.8"},
		},
		packageGen: 1000,
		distGen:    1500,
		repoGen:    500,
	},
}

// setupIndexE2E creates and configures an indexE2e instance
func setupIndexE2E(ctx context.Context, pool *pgxpool.Pool, scenario indexE2e, t testing.TB) *indexE2e {
	store := NewIndexerStore(pool)

	layer := &claircore.Layer{
		Hash: test.RandomSHA256Digest(t),
	}
	manifest := claircore.Manifest{
		Hash:   test.RandomSHA256Digest(t),
		Layers: []*claircore.Layer{layer},
	}

	return &indexE2e{
		name:       scenario.name,
		store:      store,
		ctx:        ctx,
		manifest:   manifest,
		scnrs:      scenario.scnrs,
		packageGen: scenario.packageGen,
		distGen:    scenario.distGen,
		repoGen:    scenario.repoGen,
	}
}
