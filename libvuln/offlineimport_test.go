package libvuln

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

var importFile *string

func init() {
	flag.Func(`load-file`, "run the integration test reading from `FILE` (must be zstd compressed)", func(v string) error {
		importFile = &v
		return nil
	})
}

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

// TestLiveOfflineImport is meant to be used for profiling and testing the
// system on a "real" export as produced by `clairctl`.
func TestOfflineImport(t *testing.T) {
	if importFile == nil {
		t.Skip(`needed flag "-load-file" not provided`)
	}
	integration.NeedDB(t)

	t.Run("Old", testOneOfflineImport(oldOfflineImport))
	t.Run("New", testOneOfflineImport(OfflineImport))
}

func testOneOfflineImport(inner func(context.Context, *pgxpool.Pool, io.Reader) error) func(*testing.T) {
	return func(t *testing.T) {
		ctx := test.Logging(t)

		f, err := os.Open(*importFile)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		zr, err := zstd.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()

		pool := pgtest.TestMatcherDB(ctx, t)
		if err := inner(ctx, pool, zr); err != nil {
			t.Error(err)
		}
	}
}

// OldOfflineImport is a copy of the previous implementation of [OfflineImport],
// kept here for the above test.
func oldOfflineImport(ctx context.Context, pool *pgxpool.Pool, in io.Reader) error {
	s := postgres.NewMatcherStore(pool)
	l, err := jsonblob.NewLoader(ctx, in)
	if err != nil {
		return err
	}

	ops, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		return err
	}

Update:
	for l.Next() {
		e := l.Entry()
		log := slog.With("updater", e.Updater)
		for _, op := range ops[e.Updater] {
			// This only helps if updaters don't keep something that
			// changes in the fingerprint.
			if op.Fingerprint == e.Fingerprint {
				log.InfoContext(ctx, "fingerprint match, skipping")
				continue Update
			}
		}
		var ref uuid.UUID
		if e.Enrichment != nil {
			if ref, err = s.UpdateEnrichments(ctx, e.Updater, e.Fingerprint, e.Enrichment); err != nil {
				return fmt.Errorf("updating enrichements: %w", err)
			}
		}
		if e.Vuln != nil {
			if ref, err = s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln); err != nil {
				return fmt.Errorf("updating vulnerabilities: %w", err)
			}
		}
		log.InfoContext(ctx, "update imported",
			"ref", ref,
			"vuln_count", len(e.Vuln),
			"enrichment_count", len(e.Enrichment))
	}
	if err := l.Err(); err != nil {
		return err
	}
	return nil
}
