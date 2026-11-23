package postgres

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

// TestUpdateEnrichmentsAtomic confirms an in-progress or failed enrichment
// update is never selected by latest_update_operations, even if another
// process refreshes the view during the update.
func TestUpdateEnrichmentsAtomic(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)
	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	const (
		name = "test-enrichment-updater"
		tag  = "CVE-0000-0000"
	)
	errInterrupted := errors.New("interrupted")

	checkEnrichment := func(t *testing.T, want int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `REFRESH MATERIALIZED VIEW CONCURRENTLY latest_update_operations;`); err != nil {
			t.Fatalf("failed to refresh view: %v", err)
		}
		res, err := store.GetEnrichment(ctx, name, []string{tag})
		if err != nil {
			t.Fatalf("failed to get enrichment: %v", err)
		}
		if len(res) != 1 {
			t.Fatalf("got %d enrichments, want 1", len(res))
		}
		var got struct{ V int }
		if err := json.Unmarshal(res[0].Enrichment, &got); err != nil {
			t.Fatal(err)
		}
		if got.V != want {
			t.Errorf("got enrichment version %d, want %d", got.V, want)
		}
	}

	_, err := store.UpdateEnrichments(ctx, name, driver.Fingerprint(uuid.New().String()), []driver.EnrichmentRecord{
		{Tags: []string{tag}, Enrichment: json.RawMessage(`{"v":1}`)},
	})
	if err != nil {
		t.Fatalf("failed initial update: %v", err)
	}
	checkEnrichment(t, 1)

	_, err = store.UpdateEnrichmentsIter(ctx, name, driver.Fingerprint(uuid.New().String()), func(yield func(*driver.EnrichmentRecord, error) bool) {
		if !yield(&driver.EnrichmentRecord{Tags: []string{tag}, Enrichment: json.RawMessage(`{"v":2}`)}, nil) {
			return
		}
		// Simulate another matcher refreshing the view mid-update.
		checkEnrichment(t, 1)
		yield(nil, errInterrupted)
	})
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("got error %v, want %v", err, errInterrupted)
	}
	checkEnrichment(t, 1)

	ops, err := store.GetUpdateOperations(ctx, driver.EnrichmentKind, name)
	if err != nil {
		t.Fatalf("failed to get update operations: %v", err)
	}
	if got := len(ops[name]); got != 1 {
		t.Errorf("got %d update operations, want 1", got)
	}
}
