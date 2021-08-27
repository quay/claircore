package rhel

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	vulnstore "github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/updates"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
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
	pool := vulnstore.TestDB(ctx, t)
	store := vulnstore.NewVulnStore(pool)
	m := &Matcher{}
	fs, err := filepath.Glob("testdata/*.xml")
	if err != nil {
		t.Error(err)
	}
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		t.Error(err)
	}
	defer locks.Close(ctx)

	facs := make(map[string]driver.UpdaterSetFactory, len(fs))
	for _, f := range fs {
		u, err := test.Updater(f)
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
	mgr, err := updates.NewManager(ctx, store, locks, http.DefaultClient, updates.WithFactories(facs))
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
	if err := json.NewEncoder(ioutil.Discard).Encode(&vr); err != nil {
		t.Fatalf("failed to marshal VR: %v", err)
	}
}

type vulnerableTestCase struct {
	ir   *claircore.IndexRecord
	v    *claircore.Vulnerability
	want bool
	name string
}

func TestVulnerable(t *testing.T) {
	record := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
	}
	fixedVulnPast := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-5.el8",
	}
	fixedVulnCurrent := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-6.el8",
	}
	fixedVulnFuture := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-7.el8",
	}
	unfixedVuln := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
	}

	testCases := []vulnerableTestCase{
		{ir: record, v: fixedVulnPast, want: false, name: "vuln fixed in past version"},
		{ir: record, v: fixedVulnCurrent, want: false, name: "vuln fixed in current version"},
		{ir: record, v: fixedVulnFuture, want: true, name: "outdated package"},
		{ir: record, v: unfixedVuln, want: true, name: "unfixed vuln"},
	}

	m := &Matcher{}

	for _, tc := range testCases {
		got, err := m.Vulnerable(nil, tc.ir, tc.v)
		if err != nil {
			t.Error(err)
		}
		if tc.want != got {
			t.Errorf("%q failed: want %t, got %t", tc.name, tc.want, got)
		}
	}
}
