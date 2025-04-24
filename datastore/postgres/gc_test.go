package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

var _ driver.Updater = (*updaterMock)(nil)

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

var (
	_ driver.Updater           = (*enricherMock)(nil)
	_ driver.EnrichmentUpdater = (*enricherMock)(nil)
)

type enricherMock struct {
	driver.NoopUpdater
	_name  func() string
	_fetch func(_ context.Context, _ driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error)
	_parse func(ctx context.Context, contents io.ReadCloser) ([]driver.EnrichmentRecord, error)
}

func (e enricherMock) Name() string {
	return e._name()
}

func (e enricherMock) FetchEnrichment(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	return e._fetch(ctx, fingerprint)
}

func (e enricherMock) ParseEnrichment(ctx context.Context, contents io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	return e._parse(ctx, contents)
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

	// mock returns exactly one random enrichment each time its Parse method is called.
	// each update operation will be associated with a single enrichment.
	mockEnrich := &enricherMock{
		_name: func() string { return "MockEnrichmentUpdater" },
		_fetch: func(_ context.Context, _ driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
			return nil, "", nil
		},
		_parse: func(ctx context.Context, contents io.ReadCloser) ([]driver.EnrichmentRecord, error) {
			return []driver.EnrichmentRecord{
				{
					Tags:       []string{randString(t)},
					Enrichment: json.RawMessage("{}"),
				},
			}, nil
		},
	}

	// these tests maintain a one:one relationship between
	// update operations and a linked vulnerability for simplicty.
	// in other words, each update operation inserts one vuln and
	// each deletion of an update operation should induce a deletion
	// of one vuln.
	table := []struct {
		// name of test case
		name string
		// number of update operations to create
		updateOps int
		// number of update operations to keep
		keep int
	}{
		{
			"Small",
			4,
			3,
		},
		{
			"Large",
			100,
			50,
		},
		{
			"Odd",
			37,
			23,
		},
		{
			"Inversed",
			10,
			50,
		},
		{
			"Throttle",
			60,
			5,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			pool := pgtest.TestMatcherDB(ctx, t)
			store := NewMatcherStore(pool)
			locks, err := ctxlock.New(ctx, pool)
			if err != nil {
				t.Error(err)
			}
			defer locks.Close(ctx)
			mgr, err := updates.NewManager(
				ctx,
				NewMatcherStore(pool),
				locks,
				http.DefaultClient, // Used on purpose -- shouldn't actually get called by anything.
				updates.WithEnabled([]string{}),
				updates.WithFactories(map[string]driver.UpdaterSetFactory{
					"MockEnrichmentUpdater": func() driver.UpdaterSetFactory {
						set := driver.NewUpdaterSet()
						_ = set.Add(mockEnrich)
						return driver.StaticSet(set)
					}(),
				}),
				updates.WithOutOfTree([]driver.Updater{mock}),
			)
			if err != nil {
				t.Fatalf("failed creating update manager: %v", err)
			}

			t.Logf("update Opts: %d", tt.updateOps)
			// run updater n times to create n update operations
			for range tt.updateOps {
				err := mgr.Run(ctx)
				if err != nil {
					t.Fatalf("manager failed to run: %v", err)
				}
			}

			// confirm update operations exist
			ops, err := store.GetUpdateOperations(ctx, driver.VulnerabilityKind)
			if err != nil {
				t.Fatalf("failed obtaining update ops: %v", err)
			}
			if len(ops["MockUpdater"]) != tt.updateOps {
				t.Fatalf("%s got: %v want: %v", tt.name, len(ops["MockUpdater"]), tt.updateOps)
			}
			ops, err = store.GetUpdateOperations(ctx, driver.EnrichmentKind)
			if err != nil {
				t.Fatalf("failed obtaining enrichment update ops: %v", err)
			}
			if len(ops["MockEnrichmentUpdater"]) != tt.updateOps {
				t.Fatalf("%s got: %v want: %v", tt.name, len(ops["MockEnrichmentUpdater"]), tt.updateOps)
			}

			// run gc
			expectedNotDone := max(2*(tt.updateOps-tt.keep)-GCThrottle, 0)
			notDone, err := store.GC(ctx, tt.keep)
			switch {
			case err != nil:
				t.Fatalf("error while performing GC: %v", err)
			case notDone != int64(expectedNotDone):
				t.Fatalf("%s got: %v, want: %v", tt.name, notDone, expectedNotDone)
			}

			wantKeep := tt.keep
			if tt.updateOps < tt.keep {
				wantKeep = tt.updateOps
			}
			expectedRemaining := 2*wantKeep + expectedNotDone

			updaterOps, err := store.GetUpdateOperations(ctx, driver.VulnerabilityKind)
			if err != nil {
				t.Fatalf("failed obtaining update ops: %v", err)
			}
			t.Logf("ops %v", updaterOps)
			enricherOps, err := store.GetUpdateOperations(ctx, driver.EnrichmentKind)
			if err != nil {
				t.Fatalf("failed obtaining enrichment update ops: %v", err)
			}
			t.Logf("ops %v", enricherOps)
			if len(updaterOps["MockUpdater"])+len(enricherOps["MockEnrichmentUpdater"]) != expectedRemaining {
				t.Fatalf("%s got: %v want: %v", tt.name, len(updaterOps["MockUpdater"])+len(enricherOps["MockEnrichmentUpdater"]), expectedRemaining)
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
