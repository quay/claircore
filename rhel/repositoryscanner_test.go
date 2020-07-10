package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/test/log"
)

func TestRepositoryScanner(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

	// Set up a response map and test server to mock the Container API.
	resp := map[string]*containerImages{
		"rh-pkg-1-1": &containerImages{Images: []containerImage{
			{
				CPE: []string{
					"cpe:/o:redhat:enterprise_linux:8::computenode",
					"cpe:/o:redhat:enterprise_linux:8::baseos",
				},
				ParsedData: parsedData{
					Architecture: "x86_64",
					Labels: []label{
						{Name: "architecture", Value: "x86_64"},
					},
				},
			},
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.String())
		nvr := path.Base(r.URL.Path)
		if err := json.NewEncoder(w).Encode(resp[nvr]); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	table := []struct {
		name      string
		cfg       *RepoScannerConfig
		want      []*claircore.Repository
		layerPath string
	}{
		{
			name: "FromAPI",
			want: []*claircore.Repository{
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::computenode",
					Key:  "rhel-cpe-repo",
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::computenode"),
				},
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  "rhel-cpe-repo",
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
			},
			cfg:       &RepoScannerConfig{API: srv.URL},
			layerPath: "testdata/layer-with-cpe.tar",
		},
		{
			name:      "No-cpe-info",
			want:      nil,
			layerPath: "testdata/layer-with-no-cpe-info.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &RepositoryScanner{}
			l := &claircore.Layer{}
			l.SetLocal(tt.layerPath)

			if tt.cfg != nil {
				var buf bytes.Buffer
				if err := json.NewEncoder(&buf).Encode(&tt.cfg); err != nil {
					t.Error(err)
				}
				if err := scanner.Configure(ctx, json.NewDecoder(&buf).Decode, srv.Client()); err != nil {
					t.Error(err)
				}
			}

			got, err := scanner.Scan(ctx, l)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, tt.want) {
				t.Error(cmp.Diff(got, tt.want))
			}
		})
	}
}
