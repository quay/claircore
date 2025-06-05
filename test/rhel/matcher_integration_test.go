package rhel

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
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func serveOVAL(t *testing.T) (string, *http.Client) {
	srv := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

func TestMatcherIntegration(t *testing.T) {
	t.Parallel()
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := pgtest.TestMatcherDB(ctx, t)
	store := postgres.NewMatcherStore(pool)
	m := &rhel.Matcher{}
	fs, err := filepath.Glob("testdata/*.xml")
	if err != nil {
		t.Error(err)
	}
	root, c := serveOVAL(t)
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Error(err)
		return
	}
	defer locks.Close(ctx)

	facs := make(map[string]driver.UpdaterSetFactory, len(fs))
	for _, fn := range fs {
		u, err := rhel.NewUpdater(
			fmt.Sprintf("test-updater-%s", filepath.Base(fn)),
			1,
			root+"/"+filepath.Base(fn),
			false,
		)
		if err != nil {
			t.Error(err)
			continue
		}
		u.Configure(ctx, func(v interface{}) error { return nil }, c)
		if err != nil {
			t.Error(err)
			continue
		}
		s := driver.NewUpdaterSet()
		if err := s.Add(u); err != nil {
			t.Error(err)
			continue
		}
		facs[u.Name()] = driver.StaticSet(s)
	}
	mgr, err := updates.NewManager(ctx, store, locks, c, updates.WithFactories(facs))
	if err != nil {
		t.Error(err)
	}
	// force update
	if err := mgr.Run(ctx); err != nil {
		t.Error(err)
	}

	f, err := os.Open(filepath.Join("testdata", "rhel-report.json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer f.Close()
	var ir claircore.IndexReport
	if err := json.NewDecoder(f).Decode(&ir); err != nil {
		t.Fatalf("failed to decode IndexReport: %v", err)
	}
	vr, err := matcher.Match(ctx, &ir, []driver.Matcher{m}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(io.Discard).Encode(&vr); err != nil {
		t.Fatalf("failed to marshal VR: %v", err)
	}
}

type vulnerableTestCase struct {
	ir   *claircore.IndexRecord
	v    *claircore.Vulnerability
	name string
	want bool
}

func TestVulnerable(t *testing.T) {
	record := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::baseos"),
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	openshiftRecord := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			Name: "cpe:/a:redhat:openshift:4.13::el8",
			Key:  "rhel-cpe-repository",
		},
	}
	openshift5Record := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/a:redhat:openshift:5.1::el8"),
			Name: "cpe:/a:redhat:openshift:5.1::el8",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnPast := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-5.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnCurrent := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-6.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnFuture := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-7.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVuln := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnBadCPE := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cep:o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoIsSubset := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoNotSubset := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoSubstring := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/a:redhat:openshift:4",
			Key:  "rhel-cpe-repository",
		},
	}
	genericWilcardRepo := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/a:redhat:openshift:4.%02::el8",
			Key:  "rhel-cpe-repository",
		},
	}

	testCases := []vulnerableTestCase{
		{ir: record, v: fixedVulnPast, want: false, name: "vuln fixed in past version"},
		{ir: record, v: fixedVulnCurrent, want: false, name: "vuln fixed in current version"},
		{ir: record, v: fixedVulnFuture, want: true, name: "outdated package"},
		{ir: record, v: unfixedVuln, want: true, name: "unfixed vuln"},
		{ir: record, v: unfixedVulnBadCPE, want: false, name: "unfixed vuln, invalid CPE"},
		{ir: record, v: unfixedVulnRepoIsSubset, want: true, name: "unfixed vuln, Repo is a subset"},
		{ir: record, v: unfixedVulnRepoNotSubset, want: false, name: "unfixed vuln, Repo not a subset"},
		{ir: openshiftRecord, v: unfixedVulnRepoSubstring, want: true, name: "unfixed vuln, Repo is a substring match"},
		{ir: openshiftRecord, v: genericWilcardRepo, want: true, name: "unfixed vuln, Repo is a superset (with wildcard)"},
		{ir: openshift5Record, v: genericWilcardRepo, want: false, name: "unfixed vuln, Repo isn't a superset (with wildcard)"},
	}

	m := &rhel.Matcher{}
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)
	for _, tc := range testCases {
		got, err := m.Vulnerable(ctx, tc.ir, tc.v)
		if err != nil {
			t.Error(err)
		}
		if tc.want != got {
			t.Errorf("%q failed: want %t, got %t", tc.name, tc.want, got)
		}
	}
}
