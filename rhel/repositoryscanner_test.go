package rhel

import (
	"bytes"
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

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestRepositoryScanner(t *testing.T) {
	t.Parallel()

	repoData := `
	{
		"data": {
			"content-set-1": {
				"cpes": ["cpe:/o:redhat:enterprise_linux:6::server", "cpe:/o:redhat:enterprise_linux:7::server"]
			},
			"content-set-2": {
				"cpes": ["cpe:/o:redhat:enterprise_linux:7::server", "cpe:/o:redhat:enterprise_linux:8::server"]
			},
			"content-set-3": {
				"cpes": ["cpe:/o:redhat:enterprise_linux:8::server", "cpe:/o:redhat:enterprise_linux:9::server"]
			},
			"content-set-4": {
				"cpes": ["cpe:/o:redhat:enterprise_linux:9::server", "cpe:/o:redhat:enterprise_linux:10::server"]
			}
		}
	}
	`
	mappingData := strings.NewReader(repoData)
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
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name: "FromMappingFile",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/layer-with-embedded-cs.tar",
		},
		{
			name: "FromMappingFileAirGap",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
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
		},
		{
			name:      "BadContentManifestsFile",
			want:      nil,
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingURL: srv.URL + "/repository-2-cpe.json"},
			layerPath: "testdata/layer-with-invalid-content-manifests-json.tar",
		},
		{
			name: "RHCOSLayerFromMappingFile",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/rhcos-layer-with-embedded-cs.tar",
		},
		{
			name: "RHCOSLayerFromMappingFileWithConflictingFiles",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/rhcos-layer-with-conflicting-files.tar",
		},
		{
			name: "FromDNFHintTrueUsesDNF",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:10:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:10::server"),
					URI:  "repoid=content-set-4",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-3",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::server"),
					URI:  "repoid=content-set-3",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::server"),
					URI:  "repoid=content-set-4",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/layer-dnf-hint-true.tar",
		},
		{
			name: "NoFromDNFHintField_UsesContentSets",
			want: []*claircore.Repository{
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:6:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-1",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:7:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7::server"),
					URI:  "repoid=content-set-2",
				},
				{
					Name: "cpe:2.3:o:redhat:enterprise_linux:8:*:server:*:*:*:*:*",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::server"),
					URI:  "repoid=content-set-2",
				},
			},
			cfg:       &RepositoryScannerConfig{Repo2CPEMappingFile: f.Name()},
			layerPath: "testdata/layer-with-embedded-cs.tar", // Existing test data with no from_dnf_hint field
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := test.Logging(t)
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

func TestBugURL(t *testing.T) {
	const in = `cpe:/a:redhat:openshift:4.*`
	const want = `https://issues.redhat.com/secure/CreateIssueDetails%21init.jspa?description=A+Clair+instance+noticed+an+invalid+CPE%3A%7Bcode%7Dcpe%3A%2Fa%3Aredhat%3Aopenshift%3A4.%2A%7Bcode%7D%0AThe+reported+error+was%3A%7Bcode%7Dcpe%3A+version%3A+disallowed+character+%27%2A%27%7Bcode%7D&issuetype=1&pid=12330022&summary=invalid+CPE+in+Red+Hat+data`

	_, err := cpe.Unbind(in)
	if err == nil {
		t.Error("expected error")
	}
	got := bugURL(in, err).String()

	t.Logf("\ngot:  %s\nwant: %s", got, want)
	if got != want {
		t.Fail()
	}
}
