package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

func TestRepositoryScanner(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	// Set up a response map and test server to mock the Container API.
	apiData := map[string]*strings.Reader{
		"rh-pkg-1-1": strings.NewReader(`{"data":[{"cpe_ids":["cpe:/o:redhat:enterprise_linux:8::computenode","cpe:/o:redhat:enterprise_linux:8::baseos"],"parsed_data":{"architecture":"x86_64","labels":[{"name":"architecture","value":"x86_64"}]}}]}`),
	}
	mappingData := strings.NewReader(`{"data":{"content-set-1":{"cpes":["cpe:/o:redhat:enterprise_linux:6::server","cpe:/o:redhat:enterprise_linux:7::server"]},"content-set-2":{"cpes":["cpe:/o:redhat:enterprise_linux:7::server","cpe:/o:redhat:enterprise_linux:8::server"]}}}`)

	mux := http.NewServeMux()
	mux.HandleFunc("/repository-2-cpe.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("last-modified", "Mon, 02 Jan 2006 15:04:05 MST")
		if _, err := mappingData.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, mappingData); err != nil {
			t.Fatal(err)
		}
	})
	mux.HandleFunc("/v1/images/nvr/", func(w http.ResponseWriter, r *http.Request) {
		path := path.Base(r.URL.Path)
		d := apiData[path]
		if _, err := d.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, d); err != nil {
			t.Fatal(err)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	table := []struct {
		cfg       *RepositoryScannerConfig
		name      string
		layerPath string
		want      []*claircore.Repository
	}{
		{
			name: "FromAPI",
			want: []*claircore.Repository{
				{
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					Name: "cpe:/o:redhat:enterprise_linux:8::computenode",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::computenode"),
				},
			},
			cfg:       &RepositoryScannerConfig{API: srv.URL, Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-cpe.tar",
		},
		{
			name: "From mapping file",
			want: []*claircore.Repository{
				{
					Name: "cpe:/o:redhat:enterprise_linux:6::server",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
				},
				{
					Name: "cpe:/o:redhat:enterprise_linux:7::server",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
				},
				{
					Name: "cpe:/o:redhat:enterprise_linux:8::server",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
				},
			},
			cfg:       &RepositoryScannerConfig{API: srv.URL, Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name:      "No-cpe-info",
			want:      nil,
			cfg:       &RepositoryScannerConfig{},
			layerPath: "testdata/layer-with-no-cpe-info.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			scanner := new(RepositoryScanner)
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
			sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
			if !cmp.Equal(got, tt.want) {
				t.Error(cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestLabelError(t *testing.T) {
	err := missingLabel("test")
	t.Log(err)
	if got, want := err, errBadDockerfile; !errors.Is(got, want) {
		t.Errorf("%v != %v", got, want)
	}
	if got, want := err, missingLabel("test"); !errors.Is(got, want) {
		t.Errorf("%v != %v", got, want)
	}
}
