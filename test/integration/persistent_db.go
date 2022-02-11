package integration

import (
	"context"
	"fmt"
	"testing"
)

// NewPersistentDB creates a database for use in integration tests.
//
// Unlike the NewDB function, this function uses a deterministic role and
// database name, and does not drop the database during cleanup.
// The "uuid-ossp" extension is already loaded.
//
// DBSetup and NeedDB are expected to have been called correctly.
func NewPersistentDB(ctx context.Context, t testing.TB, id string) *DB {
	database := fmt.Sprintf("db_%s", id)
	role := fmt.Sprintf("role_%s", id)
	cfg := configureDatabase(ctx, t, pkgConfig, database, role)
	if cfg == nil {
		t.FailNow()
	}
	db := DB{
		cfg:    cfg,
		noDrop: true,
	}
	return &db
}
