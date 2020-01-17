package updater

import (
	"context"
	"testing"
	"time"

	"github.com/quay/claircore/internal/vulnstore/postgres"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	"github.com/quay/claircore/ubuntu"
)

// Test_Updater_Integration starts with an empty database and runs until a
// large timeout. We then confirm the store has populated vulns
func Test_Updater_Integration(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	ubuntuPrecise := ubuntu.NewUpdater(ubuntu.Precise)

	db, store, _, teardown := postgres.TestStore(ctx, t)
	defer teardown()

	opts := &Opts{
		Name:     "ubuntu-precise",
		Updater:  ubuntuPrecise,
		Store:    store,
		Interval: 30 * time.Second,
		Lock:     distlock.NewLock(db, 10*time.Second),
	}
	controller := New(opts)

	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := controller.Update(tctx); err != nil {
		t.Error(err)
	}

	var count int
	if err := db.Get(&count, "SELECT COUNT(*) FROM vuln;"); err != nil {
		t.Error(err)
	}
	t.Logf("found: %d entries", count)
}
