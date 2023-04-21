package python

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
		t.Fatalf("%v", err)
	}
	defer locks.Close(ctx)

	cfg := map[string]driver.ConfigUnmarshaler{
		"osv": func(v interface{}) error {
			cfg := v.(*osv.Config)
			cfg.URL = osv.DefaultURL
			return nil
		},
	}

	facs := map[string]driver.UpdaterSetFactory{
		"osv": osv.Factory,
	}
	mgr, err := updates.NewManager(ctx, store, locks, srv.Client(),
		updates.WithFactories(facs), updates.WithConfigs(cfg))
	if err != nil {
		t.Fatalf("%v", err)
	}

	// force update
	if err := mgr.Run(ctx); err != nil {
		t.Fatalf("%v", err)
	}

	path := filepath.Join("testdata", "indexreport-buster-rhel8-databind.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%v", err)
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

	vulns := vr.Vulnerabilities
	t.Logf("Number of Vulnerabilities found: %d", len(vulns))

	if len(vulns) < 1 {
		t.Fatalf("failed to match vulns: %v", err)
	}
}
