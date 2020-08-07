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
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/rhel/repo2cpe"
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
				CPEs: []string{
					"cpe:/o:redhat:enterprise_linux:8::computenode",
					"cpe:/o:redhat:enterprise_linux:8::baseos",
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
	mappingData := repo2cpe.MappingFile{Data: map[string]repo2cpe.Repo{
		"content-set-1": repo2cpe.Repo{
			CPEs: []string{"cpe:/o:redhat:enterprise_linux:6::server", "cpe:/o:redhat:enterprise_linux:7::server"},
		},
		"content-set-2": repo2cpe.Repo{
			CPEs: []string{"cpe:/o:redhat:enterprise_linux:7::server", "cpe:/o:redhat:enterprise_linux:8::server"},
		},
	}}

	mux := http.NewServeMux()
	mux.HandleFunc("/repository-2-cpe.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("last-modified", "Mon, 02 Jan 2006 15:04:05 MST")
		if err := json.NewEncoder(w).Encode(mappingData); err != nil {
			t.Fatal(err)
		}
	})
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
					Name: "cpe:/o:redhat:enterprise_linux:8::computenode",
					Key:  RedHatRepositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::computenode"),
				},
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  RedHatRepositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
			},
			cfg:       &RepoScannerConfig{API: srv.URL, Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-cpe.tar",
		},
		{
			name: "From mapping file",
			want: []*claircore.Repository{
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:6::server",
					Key:  RedHatRepositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
				},
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:7::server",
					Key:  RedHatRepositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
				},
				&claircore.Repository{
					Name: "cpe:/o:redhat:enterprise_linux:8::server",
					Key:  RedHatRepositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
				},
			},
			cfg:       &RepoScannerConfig{API: srv.URL, Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name:      "No-cpe-info",
			want:      nil,
			cfg:       &RepoScannerConfig{},
			layerPath: "testdata/layer-with-no-cpe-info.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewRepositoryScanner(ctx, nil, tt.cfg.Repo2CPEMappingURL)
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
