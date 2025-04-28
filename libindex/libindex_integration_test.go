package libindex

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/linux"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	indexer "github.com/quay/claircore/test/mock/indexer"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/whiteout"
)

// Testcase is a test case for calling libindex.
type testcase struct {
	// Packages is the number of packages to generate for each layer.
	Packages []int
	// Layers is the number of layers to place in the manifest under test.
	Layers int
	// Scanners is the number of mock scanners to create. Must be at least 1.
	Scanners int
}

// Name returns a unique name for the test
func (tc testcase) Name() string {
	var b strings.Builder
	for i, n := range tc.Packages {
		if i != 0 {
			b.WriteByte(':')
		}
		fmt.Fprint(&b, n)
	}
	return fmt.Sprintf("%dlayer_%spackage_%dscanner", tc.Layers, b.String(), tc.Scanners)
}

// Digest returns a sham digest, for use in a manifest.
func (tc testcase) Digest() claircore.Digest {
	h := sha256.New()
	io.WriteString(h, tc.Name())
	d, err := claircore.NewDigest("sha256", h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return d
}

// RunInner "exposes" just the test logic.
func (tc testcase) RunInner(ctx context.Context, t *testing.T, pool *pgxpool.Pool, next checkFunc) {
	ms := []*indexer.MockPackageScanner{}
	ctrl := gomock.NewController(t)

	// create the desired number of package scanners. we will
	// configure the Scan() method on the mock when generated layers below
	for i := 0; i < tc.Scanners; i++ {
		m := indexer.NewMockPackageScanner(ctrl)
		m.EXPECT().Name().AnyTimes().Return(fmt.Sprintf("test-scanner-%d", i))
		m.EXPECT().Version().AnyTimes().Return("v0.0.1")
		m.EXPECT().Kind().AnyTimes().Return("package")
		ms = append(ms, m)
	}

	// configure scanners to return the desired pkg counts
	for i := 0; i < tc.Layers; i++ {
		// generate the desired number of package we'll return for this layer
		pkgs := test.GenUniquePackages(tc.Packages[i])

		// configure the desired scanners to return this set of pkgs when their Scan()
		// are called.
		for _, m := range ms {
			m.EXPECT().Scan(gomock.Any(), gomock.Any()).Return(pkgs, nil)
		}
	}
	c, descs := test.ServeLayers(t, tc.Layers)

	// create manifest
	m := &claircore.Manifest{
		Hash:   tc.Digest(),
		Layers: wart.DescriptionsToLayers(descs),
	}

	store, err := postgres.InitPostgresIndexerStore(ctx, pool, false)
	if err != nil {
		t.Fatalf("failed to create postgres connection: %v", err)
	}

	ctxLocker, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Fatalf("failed to create context locker: %v", err)
	}

	// create libindex instance
	opts := &Options{
		Store:                store,
		Locker:               ctxLocker,
		FetchArena:           NewRemoteFetchArena(c, t.TempDir()),
		ScanLockRetry:        2 * time.Second,
		LayerScanConcurrency: 1,
		Ecosystems: []*indexer.Ecosystem{
			{
				PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
					ps := make([]indexer.PackageScanner, len(ms))
					for i := range ms {
						ps[i] = ms[i]
					}
					return ps, nil
				},
				DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
					return nil, nil
				},
				RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
					return nil, nil
				},
				FileScanners: func(ctx context.Context) ([]indexer.FileScanner, error) {
					return []indexer.FileScanner{&whiteout.Scanner{}}, nil
				},
				Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
					return linux.NewCoalescer(), nil
				},
				Name: "test",
			},
		},
	}

	lib, err := New(ctx, opts, c)
	if err != nil {
		t.Fatalf("failed to create libindex instance: %v", err)
	}
	defer lib.Close(ctx)

	// setup scan and run
	ir, err := lib.Index(ctx, m)
	if err != nil {
		t.Fatalf("failed to scan manifest: %v", err)
	}

	next(ctx, t, tc, lib, ir)
}

// Run does per-test setup and calls RunInner
func (tc testcase) Run(ctx context.Context, check checkFunc) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		integration.NeedDB(t)
		ctx := zlog.Test(ctx, t)
		pool := pgtest.TestIndexerDB(ctx, t)
		tc.RunInner(ctx, t, pool, check)
	}
}

// CheckFunc is used by a testcase to check the result after the generic setup.
type checkFunc func(context.Context, *testing.T, testcase, *Libindex, *claircore.IndexReport)

// CheckEqual is a checkFunc that does what it says on the tin.
func checkEqual(ctx context.Context, t *testing.T, tc testcase, lib *Libindex, ir *claircore.IndexReport) {
	// BUG(hank) The cached and live results of an index report are different,
	// because of the JSON marshaling. This should not be the case.
	cmpopts := cmp.Options{
		cmp.AllowUnexported(claircore.Digest{}),
		cmp.FilterPath(func(p cmp.Path) bool {
			s := p.Index(-3)
			m := p.Last().String()
			return m == ".Files" || (s.Type() == reflect.TypeOf((*claircore.Package)(nil)) &&
				(m == ".RepositoryHint" || m == ".PackageDB"))
		}, cmp.Ignore()),
	}
	hash := tc.Digest()
	if got, want := ir.Hash, hash; !cmp.Equal(got, want, cmpopts) {
		t.Error(cmp.Diff(got, want, cmpopts))
	}
	if !ir.Success {
		t.Error("expected Success in IndexReport")
	}

	// confirm scan report retrieved from libindex matches the one
	// the Scan() method returned
	want := ir
	got, ok, err := lib.IndexReport(ctx, hash)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("expected ok return from IndexReport")
	}
	if !cmp.Equal(got, want, cmpopts) {
		t.Error(cmp.Diff(got, want, cmpopts))
	}
}

var testtable = []testcase{
	{
		Layers:   1,
		Packages: []int{1},
		Scanners: 1,
	},
	{
		Layers:   1,
		Packages: []int{2},
		Scanners: 2,
	},
	{
		Layers:   2,
		Packages: []int{1, 1},
		Scanners: 1,
	},
	{
		Layers:   2,
		Packages: []int{1, 1},
		Scanners: 2,
	},
	{
		Layers:   2,
		Packages: []int{2, 2},
		Scanners: 2,
	},
	{
		Layers:   3,
		Packages: []int{1, 1, 1},
		Scanners: 1,
	},
	{
		Layers:   3,
		Packages: []int{2, 2, 2},
		Scanners: 2,
	},
	{
		Layers:   3,
		Packages: []int{3, 3, 3},
		Scanners: 3,
	},
}

// TestIndex tests that our library performs a successful scan.
// we mock out the package scanners to return sets of packages generated by
// test functions.
func TestIndex(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testtable {
		t.Run(tc.Name(), tc.Run(ctx, checkEqual))
	}
}
