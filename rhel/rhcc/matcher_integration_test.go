package rhcc

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	table := []struct {
		cvemap      string
		indexReport string
		cveID       string
		match       bool
	}{
		{
			cvemap:      "cve-2021-3762",
			indexReport: "clair-rhel8-v3.5.5-4",
			cveID:       "CVE-2021-3762",
			match:       true,
		},
		{
			cvemap:      "cve-2020-8565",
			indexReport: "rook-ceph-operator-container-4.6-115.d1788e1.release_4.6",
			cveID:       "CVE-2020-8565",
			match:       true,
		},
		{
			cvemap:      "cve-2020-8565",
			indexReport: "rook-ceph-operator-container-4.7-159.76b9b11.release_4.7",
			cveID:       "CVE-2020-8565",
			match:       false,
		},
	}

	for _, tt := range table {
		t.Run(tt.indexReport, func(t *testing.T) {
			integration.NeedDB(t)
			ctx := zlog.Test(context.Background(), t)
			pool := testpostgres.TestMatcherDB(ctx, t)
			store := postgres.NewMatcherStore(pool)
			m := &matcher{}

			serveFile := fmt.Sprintf("testdata/%s.xml", tt.cvemap)

			fi, err := os.Stat(serveFile)
			if err != nil {
				t.Fatal(err)
			}
			tag := fmt.Sprintf(`"%d"`, fi.ModTime().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("etag", tag)
				http.ServeFile(w, r, serveFile)
			}))
			defer srv.Close()
			u := &updater{
				url:    srv.URL,
				client: srv.Client(),
			}
			s := driver.NewUpdaterSet()
			if err := s.Add(u); err != nil {
				t.Error(err)
			}

			locks, err := ctxlock.New(ctx, pool)
			if err != nil {
				t.Error(err)
			}
			defer locks.Close(ctx)

			facs := make(map[string]driver.UpdaterSetFactory, 1)
			facs[u.Name()] = driver.StaticSet(s)
			mgr, err := updates.NewManager(ctx, store, locks, http.DefaultClient, updates.WithFactories(facs))
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
			if err := json.NewEncoder(ioutil.Discard).Encode(&vr); err != nil {
				t.Fatalf("failed to marshal VR: %v", err)
			}
		})
	}
}
