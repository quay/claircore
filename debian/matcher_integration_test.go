package debian

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	vulnstore "github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test/integration"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

// TestMatcherIntegration confirms packages are matched
// with vulnerabilities correctly. the returned
// store from postgres.NewTestStore must have Ubuntu
// CVE data
func TestMatcherIntegration(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := vulnstore.TestDB(ctx, t)
	store := vulnstore.NewVulnStore(pool)

	m := &Matcher{}

	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Error(err)
	}
	defer locks.Close(ctx)
	facs := make(map[string]driver.UpdaterSetFactory, 1)
	upd := NewUpdater(Buster)
	set := driver.NewUpdaterSet()
	if err := set.Add(upd); err != nil {
		t.Error(err)
	} else {
		facs[upd.Name()] = driver.StaticSet(set)
	}
	mgr, err := updates.NewManager(ctx, store, locks, http.DefaultClient, updates.WithFactories(facs))
	if err != nil {
		t.Error(err)
	}
	// force update
	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := mgr.Run(tctx); err != nil {
		t.Error(err)
	}

	path := filepath.Join("testdata", "indexreport-buster-jackson-databind.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var ir claircore.IndexReport
	err = json.NewDecoder(f).Decode(&ir)
	if err != nil {
		t.Fatalf("failed to decode IndexReport: %v", err)
	}
	vr, err := matcher.Match(ctx, &ir, []driver.Matcher{m}, store)
	if err != nil {
		t.Fatalf("expected nil error but got %v", err)
	}
	_, err = json.Marshal(&vr)
	if err != nil {
		t.Fatalf("failed to marshal VR: %v", err)
	}
}
