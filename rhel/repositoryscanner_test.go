package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/quay/claircore/pkg/tmp"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRepositoryScanner(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	mappingData := strings.NewReader(`{"data":{"content-set-1":{"cpes":["cpe:/o:redhat:enterprise_linux:6::server","cpe:/o:redhat:enterprise_linux:7::server"]},"content-set-2":{"cpes":["cpe:/o:redhat:enterprise_linux:7::server","cpe:/o:redhat:enterprise_linux:8::server"]}}}`)
	var mappingDataBytes bytes.Buffer
	if _, err := io.Copy(&mappingDataBytes, mappingData); err != nil {
		t.Fatal(err)
	}

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
	srv := httptest.NewServer(mux)
	defer srv.Close()

	td := t.TempDir()
	f, err := tmp.NewFile(td, "repository-2-cpe.json")
	if err != nil {
		t.Fatal("trying to create repository-2-cpe.json for FromMappingFile test", err)
	}
	defer f.Close()

	if _, err := f.Write(mappingDataBytes.Bytes()); err != nil {
		t.Fatalf("trying to write %s for FromMappingFile test: %v", f.Name(), err)
	}

	table := []struct {
		cfg       *RepositoryScannerConfig
		name      string
		layerPath string
		want      []*claircore.Repository
	}{
		{
			name: "FromMappingUrl",
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
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name: "FromMappingFile",
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
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name: "FromMappingFileAirGap",
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
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingURL: "/", Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name:      "NoCPE",
			want:      nil,
			cfg:       &RepositoryScannerConfig{},
			layerPath: "testdata/layer-with-no-cpe-info.tar",
		},
		{
			name:      "NoCPEWithAirGap",
			want:      nil,
			cfg:       &RepositoryScannerConfig{},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		}, {
			name:      "BadContentManifestsFile",
			want:      nil,
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-invalid-content-manifests-json.tar",
		}, {
			name: "RHCOSLayerFromMappingFile",
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
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/rhcos-layer-with-embedded-cs.tar",
		}, {
			name: "RHCOSLayerFromMappingFileWithConflictingFiles",
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
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/rhcos-layer-with-conflicting-files.tar",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(tt.layerPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			}()
			scanner := new(RepositoryScanner)
			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    `sha256:` + strings.Repeat(`beef`, 16),
				URI:       `file:///dev/null`,
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			}
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})

			if tt.cfg != nil {
				var buf bytes.Buffer
				if err := json.NewEncoder(&buf).Encode(&tt.cfg); err != nil {
					t.Error(err)
				}
				if err := scanner.Configure(ctx, json.NewDecoder(&buf).Decode, srv.Client()); err != nil {
					t.Error(err)
				}
			}

			got, err := scanner.Scan(ctx, &l)
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
