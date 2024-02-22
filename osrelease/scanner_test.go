package osrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/trace"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

type parsecase struct {
	File string
	Want claircore.Distribution
}

func (c parsecase) Test(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	ctx, task := trace.NewTask(ctx, "parse test")
	defer task.End()
	trace.Log(ctx, "parse test:file", c.File)

	f, err := os.Open(filepath.Join("testdata", c.File))
	if err != nil {
		t.Errorf("unable to open file: %v", err)
	}

	got, err := toDist(ctx, f)
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
			File: "Alpine",
			Want: claircore.Distribution{
				DID:        "alpine",
				Name:       "Alpine Linux",
				VersionID:  "3.10.2",
				PrettyName: "Alpine Linux v3.10",
			},
		},
		{
			File: "Bionic",
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
			File: "Buster",
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
			File: "OpenSUSe",
			Want: claircore.Distribution{
				DID:        "opensuse-leap",
				Name:       "openSUSE Leap",
				Version:    "15.1 ",
				VersionID:  "15.1",
				CPE:        cpe.MustUnbind("cpe:/o:opensuse:leap:15.1"),
				PrettyName: "openSUSE Leap 15.1",
			},
		},
		{
			File: "Silverblue",
			Want: claircore.Distribution{
				DID:        "fedora",
				Name:       "Fedora",
				Version:    "30.20191008.1 (Workstation Edition)",
				VersionID:  "30",
				CPE:        cpe.MustUnbind("cpe:/o:fedoraproject:fedora:30"),
				PrettyName: "Fedora",
			},
		},
		{
			File: "Toolbox",
			Want: claircore.Distribution{
				DID:        "fedora",
				Name:       "Fedora",
				Version:    "30 (Container Image)",
				VersionID:  "30",
				CPE:        cpe.MustUnbind("cpe:/o:fedoraproject:fedora:30"),
				PrettyName: "Fedora",
			},
		},
		{
			File: "Ubi8",
			Want: claircore.Distribution{
				DID:        "rhel",
				Name:       "Red Hat Enterprise Linux",
				Version:    "8.0 (Ootpa)",
				VersionID:  "8.0",
				CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8.0:ga"),
				PrettyName: "Red Hat Enterprise Linux 8",
			},
		},
		{
			File: "DistrolessCorrupt",
			Want: claircore.Distribution{
				DID:             "debian",
				Name:            "Debian GNU/Linux",
				Version:         "Debian GNU/Linux 12 (bookworm)",
				VersionCodeName: "",
				VersionID:       "12",
				PrettyName:      "Distroless",
			},
		},
		{
			File: "DistrolessValid",
			Want: claircore.Distribution{
				DID:             "debian",
				Name:            "Debian GNU/Linux",
				Version:         "12 (bookworm)",
				VersionCodeName: "bookworm",
				VersionID:       "12",
				PrettyName:      "Debian GNU/Linux 12 (bookworm)",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.File, tc.Test)
	}

	ctx := context.Background()
	ms, _ := filepath.Glob("testdata/*.txtar")
	for _, m := range ms {
		name := strings.TrimSuffix(filepath.Base(m), ".txtar")
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatal(err)
			}

			var inFile, parsedFile, distFile *txtar.File
			for i, f := range ar.Files {
				switch f.Name {
				case "os-release":
					inFile = &ar.Files[i]
				case "Parsed":
					parsedFile = &ar.Files[i]
				case "Distribution":
					distFile = &ar.Files[i]
				}
			}
			if inFile == nil || parsedFile == nil || distFile == nil {
				t.Fatalf("missing files in txtar: %v / %v / %v", inFile, parsedFile, distFile)
			}

			gotKVs, err := Parse(ctx, bytes.NewReader(inFile.Data))
			if err != nil {
				t.Errorf("parse error: %v", err)
			}
			wantKVs := make(map[string]string)
			if err := json.Unmarshal(parsedFile.Data, &wantKVs); err != nil {
				t.Errorf("unmarshal error: %v", err)
			}
			if got, want := gotKVs, wantKVs; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}

			gotDist, err := toDist(ctx, bytes.NewReader(inFile.Data))
			if err != nil {
				t.Errorf("toDist error: %v", err)
			}
			wantDist := &claircore.Distribution{}
			if err := json.Unmarshal(distFile.Data, &wantDist); err != nil {
				t.Errorf("unmarshal error: %v", err)
			}
			if got, want := gotDist, wantDist; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

type layercase struct {
	Name  string
	Layer test.LayerRef
	Want  []*claircore.Distribution
}
type layerspec struct {
	From, Repo string
	Blob       claircore.Digest
}

func (lc layercase) Test(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	l := test.RealizeLayer(ctx, t, lc.Layer)
	var s Scanner

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
	t.Run("Ubuntu", func(t *testing.T) {
		tt := []layercase{
			{
				Name: "18.04",
				Layer: test.LayerRef{
					Registry: "docker.io",
					Name:     "library/ubuntu",
					Digest:   `sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a`,
				},
				Want: []*claircore.Distribution{
					{
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
			t.Run(tc.Name, tc.Test)
		}
	})
}
