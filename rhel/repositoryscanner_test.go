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
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/test/log"
)

func TestRepositoryScanner(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

	// Set up a response map and test server to mock the Container API.
	apiData := map[string]*containerapi.ContainerImages{
		"rh-pkg-1-1": &containerapi.ContainerImages{Images: []containerapi.ContainerImage{
			{
				ContentSets: []string{
					"rhel-8-for-x86_64-baseos-rpms",
					"rhel-8-for-x86_64-appstream-rpms",
				},
				ParsedData: containerapi.ParsedData{
					Architecture: "x86_64",
					Labels: []containerapi.Label{
						{Name: "architecture", Value: "x86_64"},
					},
				},
			},
		}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/images/nvr/", func(w http.ResponseWriter, r *http.Request) {
		path := path.Base(r.URL.Path)
		if err := json.NewEncoder(w).Encode(apiData[path]); err != nil {
			t.Fatal(err)
		}
	})
	srv := httptest.NewServer(mux)
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
					Name: "rhel-8-for-x86_64-baseos-rpms",
					Key:  RedHatRepositoryKey,
				},
				&claircore.Repository{
					Name: "rhel-8-for-x86_64-appstream-rpms",
					Key:  RedHatRepositoryKey,
				},
			},
			cfg:       &RepoScannerConfig{API: srv.URL},
			layerPath: "testdata/layer-with-cpe.tar",
		},
		{
			name: "From mapping file",
			want: []*claircore.Repository{
				&claircore.Repository{
					Name: "content-set-1",
					Key:  RedHatRepositoryKey,
				},
				&claircore.Repository{
					Name: "content-set-2",
					Key:  RedHatRepositoryKey,
				},
			},
			cfg:       &RepoScannerConfig{API: srv.URL},
			layerPath: "testdata/layer-with-embedded-cs.tar",
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
