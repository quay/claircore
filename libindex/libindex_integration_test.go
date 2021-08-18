package libindex

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/libindex/migrations"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
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
func (tc testcase) RunInner(ctx context.Context, t *testing.T, dsn string, next checkFunc) {
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
	c, ls := test.ServeLayers(t, tc.Layers)

	// create manifest
	m := &claircore.Manifest{
		Hash:   tc.Digest(),
		Layers: ls,
	}

	// create libindex instance
	opts := &Opts{
		ConnString:           dsn,
		ScanLockRetry:        2 * time.Second,
		LayerScanConcurrency: 1,
	}

	lib, err := New(ctx, opts, c)
	if err != nil {
		t.Fatalf("failed to create libindex instance: %v", err)
	}
	defer lib.Close(ctx)

	// setup scan and run
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ir, err := lib.Index(ctx, m)
	if err != nil {
		t.Fatalf("failed to scan manifest: %v", err)
	}

	next(ctx, t, tc, lib, ir)
}

// Run does per-test setup and calls RunInner
func (tc testcase) Run(ctx context.Context, check checkFunc) func(*testing.T) {
	const dsnFmt = `host=%s port=%d database=%s user=%s password=%s sslmode=disable`
	return func(t *testing.T) {
		t.Parallel()
		integration.NeedDB(t)
		ctx := zlog.Test(ctx, t)
		db, err := integration.NewDB(ctx, t)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close(ctx, t)
		cfg := db.Config()
		cfg.ConnConfig.LogLevel = pgx.LogLevelError
		cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
		mdb := stdlib.OpenDB(*cfg.ConnConfig)
		defer mdb.Close()
		migrator := migrate.NewPostgresMigrator(mdb)
		migrator.Table = migrations.MigrationTable
		if err := migrator.Exec(migrate.Up, migrations.Migrations...); err != nil {
			t.Fatalf("failed to perform migrations: %v", err)
		}

		// Can't use ConnString(), because it doesn't re-render the string.

		tc.RunInner(ctx, t,
			fmt.Sprintf(dsnFmt,
				cfg.ConnConfig.Host,
				cfg.ConnConfig.Port,
				cfg.ConnConfig.Database,
				cfg.ConnConfig.User,
				cfg.ConnConfig.Password),
			check)
	}
}

// CheckFunc is used by a testcase to check the result after the generic setup.
type checkFunc func(context.Context, *testing.T, testcase, *Libindex, *claircore.IndexReport)

// CheckEqual is a checkFunc that does what it says on the tin.
func checkEqual(ctx context.Context, t *testing.T, tc testcase, lib *Libindex, ir *claircore.IndexReport) {
	hash := tc.Digest()
	if got, want := ir.Hash, hash; !cmp.Equal(got, want, cmp.AllowUnexported(claircore.Digest{})) {
		t.Error(cmp.Diff(got, want))
	}
	if !ir.Success {
		t.Error("expected Success in IndexReport")
	}

	// confirm scan report retrieved from libindex matches the one
	// the Scan() method returned
	want := ir
	ir, ok, err := lib.IndexReport(ctx, hash)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("expected ok return from IndexReport")
	}
	if got := ir; !cmp.Equal(got, want, cmp.AllowUnexported(claircore.Digest{})) {
		t.Error(cmp.Diff(got, want))
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
	// No outer-test context, one is created for every parallel test.
	for _, tc := range testtable {
		tc := tc
		t.Run(tc.Name(), func(t *testing.T) {
			t.Helper()
			ctx, done := context.WithCancel(context.Background())
			defer done()
			tc.Run(ctx, checkEqual)(t)
		})
	}
}
