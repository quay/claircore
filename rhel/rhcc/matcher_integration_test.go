package rhcc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	match_engine "github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
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
		cvemap      string
		indexReport string
		cveID       string
		match       bool
	}
	table := []testcase{
		{
			Name:        "Clair",
			cvemap:      "cve-2021-3762",
			indexReport: "clair-rhel8-v3.5.5-4",
			cveID:       "RHSA-2021:3665",
			match:       true,
		},
		{
			Name:        "Rook4.6",
			cvemap:      "cve-2020-8565",
			indexReport: "rook-ceph-operator-container-4.6-115.d1788e1.release_4.6",
			cveID:       "RHSA-2021:2041",
			match:       true,
		},
		{
			Name:        "Rook4.7",
			cvemap:      "cve-2020-8565",
			indexReport: "rook-ceph-operator-container-4.7-159.76b9b11.release_4.7",
			cveID:       "RHSA-2021:2041",
			match:       false,
		},
	}

	for i := range table {
		tt := &table[i]
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			integration.NeedDB(t)
			ctx := zlog.Test(context.Background(), t)
			pool := testpostgres.TestMatcherDB(ctx, t)
			store := postgres.NewMatcherStore(pool)
			m := &matcher{}

			serveFile := filepath.Join("testdata", tt.cvemap+".xml")
			fi, err := os.Stat(serveFile)
			if err != nil {
				t.Fatal(err)
			}
			tag := fmt.Sprintf(`"%d"`, fi.ModTime().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/cvemap.xml":
					w.Header().Set("etag", tag)
					http.ServeFile(w, r, serveFile)
				case "/cvemap.xml.bz2":
					http.Error(w, "no bz2", http.StatusNotFound)
				default:
					t.Errorf("unexpected request: %s", r.URL)
					http.Error(w, "???", http.StatusNotImplemented)
				}
			}))
			defer srv.Close()
			s := driver.NewUpdaterSet()
			if err := s.Add(new(updater)); err != nil {
				t.Error(err)
			}
			cfg := updates.Configs{
				updaterName: func(v any) error {
					cfg := v.(*UpdaterConfig)
					cfg.URL = srv.URL + "/cvemap.xml"
					return nil
				},
			}

			locks, err := ctxlock.New(ctx, pool)
			if err != nil {
				t.Error(err)
			}
			defer locks.Close(ctx)

			facs := make(map[string]driver.UpdaterSetFactory, 1)
			facs[updaterName] = driver.StaticSet(s)
			mgr, err := updates.NewManager(ctx, store, locks, srv.Client(), updates.WithFactories(facs), updates.WithConfigs(cfg))
			if err != nil {
				t.Error(err)
			}

			// force update
			if err := mgr.Run(ctx); err != nil {
				t.Error(err)
			}

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
				t.Fatalf("Expected to find %s in vulnerability report", tt.cveID)
			}
			if err := json.NewEncoder(io.Discard).Encode(&vr); err != nil {
				t.Fatalf("failed to marshal VR: %v", err)
			}
		})
	}
}
