package osrelease

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/trace"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

type parsecase struct {
	File string
	Want claircore.Distribution
}

func (c parsecase) Test(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	ctx, task := trace.NewTask(ctx, "parse test")
	defer task.End()
	trace.Log(ctx, "parse test:file", c.File)

	f, err := os.Open(filepath.Join("testdata", c.File))
	if err != nil {
		t.Errorf("unable to open file: %v", err)
	}

	got, err := parse(ctx, f)
	if err != nil {
		t.Errorf("parse error: %v", err)
	}

	opts := []cmp.Option{}
	if got, want := got, &c.Want; !cmp.Equal(got, want, opts...) {
		t.Fatal(cmp.Diff(got, want, opts...))
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	tt := []parsecase{
		{
			File: "alpine",
			Want: claircore.Distribution{
				DID:        "alpine",
				Name:       "Alpine Linux",
				VersionID:  "3.10.2",
				PrettyName: "Alpine Linux v3.10",
			},
		},
		{
			File: "bionic",
			Want: claircore.Distribution{
				DID:             "ubuntu",
				Name:            "Ubuntu",
				Version:         "18.04.3 LTS (Bionic Beaver)",
				VersionID:       "18.04",
				VersionCodeName: "bionic",
				PrettyName:      "Ubuntu 18.04.3 LTS",
			},
		},
		{
			File: "buster",
			Want: claircore.Distribution{
				DID:             "debian",
				Name:            "Debian GNU/Linux",
				Version:         "10 (buster)",
				VersionID:       "10",
				VersionCodeName: "buster",
				PrettyName:      "Debian GNU/Linux 10 (buster)",
			},
		},
		{
			File: "opensuse",
			Want: claircore.Distribution{
				DID:        "opensuse-leap",
				Name:       "openSUSE Leap",
				Version:    "15.1 ",
				VersionID:  "15.1",
				CPE:        "cpe:/o:opensuse:leap:15.1",
				PrettyName: "openSUSE Leap 15.1",
			},
		},
		{
			File: "silverblue",
			Want: claircore.Distribution{
				DID:        "fedora",
				Name:       "Fedora",
				Version:    "30.20191008.1 (Workstation Edition)",
				VersionID:  "30",
				CPE:        "cpe:/o:fedoraproject:fedora:30",
				PrettyName: "Fedora",
			},
		},
		{
			File: "toolbox",
			Want: claircore.Distribution{
				DID:        "fedora",
				Name:       "Fedora",
				Version:    "30 (Container Image)",
				VersionID:  "30",
				CPE:        "cpe:/o:fedoraproject:fedora:30",
				PrettyName: "Fedora",
			},
		},
		{
			File: "ubi8",
			Want: claircore.Distribution{
				DID:        "rhel",
				Name:       "Red Hat Enterprise Linux",
				Version:    "8.0 (Ootpa)",
				VersionID:  "8.0",
				CPE:        "cpe:/o:redhat:enterprise_linux:8.0:ga",
				PrettyName: "Red Hat Enterprise Linux 8",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.File, tc.Test)
	}
}

type layercase struct {
	Name string
	URL  string
	Want []*claircore.Distribution
}

func (lc *layercase) name() string {
	return filepath.Join("testdata", lc.Name+".layer")
}

func (lc layercase) Prep(t *testing.T) {
	t.Helper()
	fn := lc.name()
	_, err := os.Stat(fn)
	switch {
	case err == nil:
		t.Logf("found layer cached: %q", fn)
		return
	case errors.Is(err, os.ErrNotExist):
		integration.Skip(t)
		t.Logf("fetching %q → %q", lc.URL, fn)
	default:
		t.Fatal(err)
	}
	f, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := http.Get(lc.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}
	rd, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if _, err := io.Copy(f, rd); err != nil {
		t.Fatal(err)
	}
	t.Logf("fetched %q", fn)
}

func (lc layercase) Test(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	s := Scanner{}
	l := &claircore.Layer{}
	if err := l.SetLocal(lc.name()); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Scan(ctx, l)
	if err != nil {
		t.Error(err)
	}
	if got, want := ds, lc.Want; !cmp.Equal(got, want) {
		t.Fatal(cmp.Diff(got, want))
	}
}

func TestLayer(t *testing.T) {
	t.Parallel()
	tt := []layercase{
		{
			Name: "ubuntu_18.04",
			URL:  "https://storage.googleapis.com/quay-sandbox-01/datastorage/registry/sha256/35/35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
			Want: []*claircore.Distribution{
				&claircore.Distribution{
					DID:             "ubuntu",
					Name:            "Ubuntu",
					Version:         "18.04.3 LTS (Bionic Beaver)",
					VersionCodeName: "bionic",
					VersionID:       "18.04",
					PrettyName:      "Ubuntu 18.04.3 LTS",
				},
			},
		},
	}

	for _, tc := range tt {
		tc.Prep(t)
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Test)
	}
}
