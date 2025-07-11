package rhel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	match_engine "github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock/v2"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/rhel/vex"
	"github.com/quay/claircore/test/integration"
	testpostgres "github.com/quay/claircore/test/postgres"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func TestMatcherIntegration(t *testing.T) {
	t.Parallel()

	type testcase struct {
		Name        string
		indexReport string
		cveID       string
		match       bool
	}
	table := []testcase{
		{
			Name:        "Clair",
			indexReport: "clair-rhel8-v3.5.5-4",
			cveID:       "CVE-2021-3762",
			match:       true,
		},
		{
			Name:        "Rook4.6",
			indexReport: "rook-ceph-operator-container-4.6-115.d1788e1.release_4.6",
			cveID:       "CVE-2020-8565",
			match:       true,
		},
		{
			Name:        "Rook4.7",
			indexReport: "rook-ceph-operator-container-4.7-159.76b9b11.release_4.7",
			cveID:       "CVE-2020-8565",
			match:       false,
		},
		{
			Name:        "Clair labels",
			indexReport: "clair-rhel8-v3.5.5-4-labels",
			cveID:       "CVE-2021-3762",
			match:       true,
		},
	}

	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := testpostgres.TestMatcherDB(ctx, t)
	store := postgres.NewMatcherStore(pool)
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Error(err)
	}
	defer locks.Close(ctx)

	root, c := vex.ServeSecDB(t, "testdata/server.txtar")
	fac := &vex.Factory{}
	cfg := updates.Configs{
		"rhel-vex": func(v any) error {
			cfg := v.(*vex.UpdaterConfig)
			cfg.URL = root + "/"
			return nil
		},
	}

	s, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	if len(s.Updaters()) != 1 {
		t.Errorf("expected 1 updater in the updaterset but got %d", len(s.Updaters()))
	}

	facs := map[string]driver.UpdaterSetFactory{"rhel-vex-fac": fac}
	mgr, err := updates.NewManager(ctx, store, locks, c, updates.WithFactories(facs), updates.WithConfigs(cfg))
	if err != nil {
		t.Error(err)
	}

	// force update
	if err := mgr.Run(ctx); err != nil {
		t.Error(err)
	}

	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			m := rhcc.Matcher

			f, err := os.Open(filepath.Join("testdata", fmt.Sprintf("%s-indexreport.json", tt.indexReport)))
			if err != nil {
				t.Fatalf("%v", err)
			}
			defer f.Close()
			var ir claircore.IndexReport
			if err := json.NewDecoder(f).Decode(&ir); err != nil {
				t.Fatalf("failed to decode IndexReport: %v", err)
			}
			vr, err := match_engine.Match(ctx, &ir, []driver.Matcher{m}, store)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			vulns := vr.Vulnerabilities
			for _, vuln := range vulns {
				t.Log(vuln.Name)
				if vuln.Name == tt.cveID {
					found = true
				}
			}
			if found != tt.match {
				t.Fatalf("Expected to find (or not) %s in vulnerability report and didn't (or did)", tt.cveID)
			}
			if err := json.NewEncoder(io.Discard).Encode(&vr); err != nil {
				t.Fatalf("failed to marshal VR: %v", err)
			}
		})
	}
}
