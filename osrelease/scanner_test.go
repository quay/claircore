package osrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ms, _ := filepath.Glob("testdata/*.txtar")
	for i := range ms {
		m := ms[i]
		name := strings.TrimSuffix(filepath.Base(m), ".txtar")
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatal(err)
			}

			// Find the correct archive members.
			var inFile, parsedFile, distFile *txtar.File
			for i, f := range ar.Files {
				switch f.Name {
				case "os-release":
					inFile = &ar.Files[i]
				case "Parsed":
					parsedFile = &ar.Files[i]
				case "Distribution":
					distFile = &ar.Files[i]
				default:
					t.Logf("unknown file: %s", f.Name)
				}
			}
			if inFile == nil {
				t.Error("missing os-release")
			}
			if parsedFile == nil {
				t.Error("missing Parsed")
			}
			if distFile == nil {
				t.Error("missing Distribution")
			}
			if t.Failed() {
				t.FailNow()
			}

			// Compare the output of [Parse].
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

			// Compare the [claircore.Distribution] output.
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
