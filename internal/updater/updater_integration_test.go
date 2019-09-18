package updater

import (
	"context"
	"testing"
	"time"

	"github.com/quay/claircore/internal/vulnstore/postgres"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/ubuntu"

	"github.com/stretchr/testify/assert"
)

// Test_Updater_Integration starts with an empty database and runs until a
// large timeout. We then confirm the store has populated vulns
func Test_Updater_Integration(t *testing.T) {
	integration.Skip(t)
	ubuntuPrecise := ubuntu.NewUpdater(ubuntu.Precise)

	db, store, teardown := postgres.NewTestStore(t)
	defer teardown()

	opts := &Opts{
		Name:     "ubuntu-precise",
		Updater:  ubuntuPrecise,
		Store:    store,
		Interval: 30 * time.Second,
		Lock:     distlock.NewLock(db, 10*time.Second),
	}
	updater := New(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	updater.Start(ctx)

	select {
	case <-ctx.Done():
	}

	var count int
	err := db.Get(&count, "SELECT COUNT(*) FROM vuln;")
	assert.NoError(t, err)
}
