package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/locksource/pglock"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres/v2"
)

type updaterMock struct {
	_name  func() string
	_fetch func(_ context.Context, _ driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error)
	_parse func(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}

func (u *updaterMock) Name() string {
	return u._name()
}

func (u *updaterMock) Fetch(ctx context.Context, fp driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	return u._fetch(ctx, fp)
}

func (u *updaterMock) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	return u._parse(ctx, contents)
}

type gcTestcase struct {
	Name      string
	UpdateOps int
	Keep      int
}

// TestGC confirms the garbage collection of
// vulnerabilities works correctly.
func TestGC(t *testing.T) {
	integration.NeedDB(t)

	// mock returns exactly one random vuln each time its Parse method is called.
	// each update operation will be associated with a single vuln.
	mock := &updaterMock{
		_name: func() string { return "MockUpdater" },
		_fetch: func(_ context.Context, _ driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
			return nil, "", nil
		},
		_parse: func(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
			return []*claircore.Vulnerability{
				{
					Name:    randString(t),
					Updater: "MockUpdater",
					Package: test.GenUniquePackages(1)[0],
				},
			}, nil
		},
	}
	max := func(x, y int) int {
		if x < y {
			return y
		}
		return x
	}

	// These tests maintain a one-to-one relationship between update operations
	// and a linked vulnerability for simplicity. In other words, each update
	// operation inserts one vulnerability and each deletion of an update
	// operation should delete one vulnerability.
	table := []gcTestcase{
		{
			Name:      "Small",
			UpdateOps: 4,
			Keep:      3,
		},
		{
			Name:      "Large",
			UpdateOps: 100,
			Keep:      50,
		},
		{
			Name:      "Odd",
			UpdateOps: 37,
			Keep:      23,
		},
		{
			Name:      "Inverted",
			UpdateOps: 10,
			Keep:      50,
		},
		{
			Name:      "Throttle",
			UpdateOps: 60,
			Keep:      5,
		},
	}

	for _, tc := range table {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			cfg := pgtest.TestMatcherDB(ctx, t)
			pool, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			store, err := NewMatcherV1(ctx, cfg, WithMigrations)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			locks, err := pglock.New(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer locks.Close()
			mgr, err := updates.NewManager(
				ctx,
				store,
				locks,
				http.DefaultClient,
				updates.WithEnabled([]string{}),
				updates.WithOutOfTree([]driver.Updater{mock}),
			)
			if err != nil {
				t.Fatalf("failed creating update manager: %v", err)
			}
			defer func() {
				if t.Failed() {
					dumptable(ctx, t, pool, "update_operation")
				}
			}()

			for i := 0; i < tc.UpdateOps; i++ {
				if err := mgr.Run(ctx); err != nil {
					t.Fatalf("manager failed to run: %v", err)
				}
			}

			// confirm update operations exist
			ops, err := store.GetUpdateOperations(ctx, driver.VulnerabilityKind)
			if err != nil {
				t.Fatalf("failed obtaining update ops: %v", err)
			}
			if got, want := len(ops[mock.Name()]), tc.UpdateOps; got != want {
				t.Fatalf("unexpected number of update operations: got: %d want: %d", got, want)
			}

			// Run GC
			expectedNotDone := max(tc.UpdateOps-tc.Keep-GCThrottle, 0)
			notDone, err := store.GC(ctx, tc.Keep)
			if err != nil {
				t.Fatalf("error while performing GC: %v", err)
			}
			if got, want := notDone, int64(expectedNotDone); got != want {
				t.Fatalf("unexpected number of leftover update operations: got: %d, want: %d", got, want)
			}

			wantKeep := tc.Keep
			if tc.UpdateOps < tc.Keep {
				wantKeep = tc.UpdateOps
			}
			ops, err = store.GetUpdateOperations(ctx, driver.VulnerabilityKind)
			if err != nil {
				t.Fatalf("failed obtaining update ops: %v", err)
			}
			//t.Logf("ops: %v", ops)
			expectedRemaining := wantKeep + expectedNotDone
			if got, want := len(ops[mock.Name()]), expectedRemaining; got != want {
				t.Fatalf("unexpected number of update operations remaining: got: %d want: %d", got, want)
			}
		})
	}
}

func randString(t *testing.T) string {
	buf := make([]byte, 4, 4)
	_, err := io.ReadAtLeast(rand.Reader, buf, len(buf))
	if err != nil {
		t.Fatalf("failed to generate random string: %v", err)
	}
	return hex.EncodeToString(buf)
}
