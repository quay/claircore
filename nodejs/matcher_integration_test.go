package nodejs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	internalMatcher "github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/updater/osv"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func TestMatcherIntegration(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := pgtest.TestMatcherDB(ctx, t)
	store := postgres.NewMatcherStore(pool)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	m := &Matcher{}
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer locks.Close(ctx)

	cfg := map[string]driver.ConfigUnmarshaler{
		"osv": func(v interface{}) error {
			cfg := v.(*osv.FactoryConfig)
			cfg.URL = osv.DefaultURL
			cfg.Allowlist = []string{"npm"}
			return nil
		},
	}

	facs := map[string]driver.UpdaterSetFactory{
		"osv": new(osv.Factory),
	}
	mgr, err := updates.NewManager(ctx, store, locks, srv.Client(),
		updates.WithFactories(facs), updates.WithConfigs(cfg))
	if err != nil {
		t.Fatal(err)
	}

	// force update
	if err := mgr.Run(ctx); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join("testdata", "indexreport-splunk-8.2.6.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ir claircore.IndexReport
	err = json.NewDecoder(f).Decode(&ir)
	if err != nil {
		t.Fatalf("failed to decode IndexReport: %v", err)
	}
	vr, err := internalMatcher.Match(ctx, &ir, []driver.Matcher{m}, store)
	if err != nil {
		t.Fatalf("expected error to be nil but got %v", err)
	}

	// List of known IDs that should be in the returned report.
	// There may be additional IDs over time, so add them here when noticed.
	need := []string{"GHSA-p8p7-x288-28g6"}

	vulns := vr.Vulnerabilities
	ids := make([]string, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.Name)
	}
	t.Logf("Number of Vulnerabilities found: %d", len(vulns))
	for _, id := range need {
		if !slices.Contains(ids, id) {
			t.Logf("missing %q", id)
			t.Error()
		}
	}
	if t.Failed() {
		t.Log(cmp.Diff(ids, need))
	}
}
