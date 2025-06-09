package debian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

// TestMatcherIntegration confirms packages are matched
// with vulnerabilities correctly. the returned
// store from postgres.NewTestStore must have Debian
// CVE data
func TestMatcherIntegration(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := pgtest.TestMatcherDB(ctx, t)
	store := postgres.NewMatcherStore(pool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case `/debian/dists/`:
			fmt.Fprintln(w, `href="buster/"`)
		case `/debian/dists/buster/Release`:
			fmt.Fprintln(w, `Origin: Debian`)
			fmt.Fprintln(w, `Label: Debian`)
			fmt.Fprintln(w, `Suite: oldstable`)
			fmt.Fprintln(w, `Version: 10.12`)
			fmt.Fprintln(w, `Codename: buster`)
		case `/`:
			tgt, err := url.Parse(debian.DefaultJSON)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", tgt.String())
			w.WriteHeader(http.StatusMovedPermanently)
		case `/debian/dists/buster/main/source/Sources.gz`,
			`/debian/dists/buster/contrib/source/Sources.gz`,
			`/debian/dists/buster/non-free/source/Sources.gz`:
			tgt, err := url.Parse(debian.DefaultMirror)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			loc, err := tgt.Parse(path.Join(tgt.Path, r.URL.Path))
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", loc.String())
			w.WriteHeader(http.StatusMovedPermanently)
		default:
			t.Logf("requested: %q", r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()

	m := &debian.Matcher{}

	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Error(err)
	}
	defer locks.Close(ctx)
	fac, err := debian.NewFactory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	facs := map[string]driver.UpdaterSetFactory{
		"debian": fac,
	}
	cfg := map[string]driver.ConfigUnmarshaler{
		"debian": func(v interface{}) error {
			cfg := v.(*debian.FactoryConfig)
			cfg.MirrorURL = srv.URL
			cfg.JSONURL = srv.URL
			return nil
		},
	}
	mgr, err := updates.NewManager(ctx, store, locks, srv.Client(),
		updates.WithFactories(facs), updates.WithConfigs(cfg))
	if err != nil {
		t.Error(err)
	}
	// force update
	if err := mgr.Run(ctx); err != nil {
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
