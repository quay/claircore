package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
		// number to update operations to keep
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
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			pool := TestDB(ctx, t)
			store := NewVulnStore(pool)
			locks, err := ctxlock.New(ctx, pool)
			if err != nil {
				t.Error(err)
			}
			defer locks.Close(ctx)
			mgr, err := updates.NewManager(
				ctx,
				NewVulnStore(pool),
				locks,
				http.DefaultClient,
				updates.WithEnabled([]string{}),
				updates.WithOutOfTree([]driver.Updater{mock}),
			)
			if err != nil {
				t.Fatalf("failed creating update manager: %v", err)
			}

			// run updater n times to create n update operations
			for i := 0; i < tt.updateOps; i++ {
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
				t.Fatalf("got: %v want: %v", len(ops["MockUpdater"]), tt.updateOps)
			}

			// run gc
			done, err := store.GC(ctx, tt.keep)
			switch {
			case err != nil:
				t.Fatalf("error while performing GC: %v", err)
			case done != 0:
				t.Fatalf("got: %v, want: %v", done, 0)
			}

			wantKeep := tt.keep
			if tt.updateOps < tt.keep {
				wantKeep = tt.updateOps
			}
			ops, err = store.GetUpdateOperations(ctx, driver.VulnerabilityKind)
			if err != nil {
				t.Fatalf("failed obtaining update ops: %v", err)
			}
			if len(ops["MockUpdater"]) != wantKeep {
				t.Fatalf("got: %v want: %v", len(ops["MockUpdater"]), wantKeep)
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
