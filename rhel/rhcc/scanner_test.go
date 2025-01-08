package rhcc

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestContainerScanner(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	clairSourceContainer := &claircore.Package{
		Name:    "quay-clair-container",
		Version: "v3.5.5-4",
		NormalizedVersion: claircore.Version{
			Kind: "rhctag",
			V:    [10]int32{3, 5},
		},
		Kind:           claircore.SOURCE,
		PackageDB:      "root/buildinfo/Dockerfile-quay-clair-rhel8-v3.5.5-4",
		RepositoryHint: "rhcc",
		Arch:           "x86_64",
	}

	quaySourceContainer := &claircore.Package{
		Name:    "quay-registry-container",
		Version: "v3.5.6-4",
		NormalizedVersion: claircore.Version{
			Kind: "rhctag",
			V:    [10]int32{3, 5},
		},
		Kind:           claircore.SOURCE,
		PackageDB:      "root/buildinfo/Dockerfile-quay-quay-rhel8-v3.5.6-4",
		RepositoryHint: "rhcc",
		Arch:           "x86_64",
	}

	loggingSourceContainer := &claircore.Package{
		Name:    "logging-elasticsearch6-container",
		Version: "v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
		NormalizedVersion: claircore.Version{
			Kind: "rhctag",
			V:    [10]int32{4, 6},
		},
		Kind:           claircore.SOURCE,
		PackageDB:      "root/buildinfo/Dockerfile-openshift-ose-logging-elasticsearch6-v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
		RepositoryHint: "rhcc",
		Arch:           "x86_64",
	}
	rhdhSourceContainer := &claircore.Package{
		Name:    "rhdh-hub-container",
		Version: "1.3-100",
		NormalizedVersion: claircore.Version{
			Kind: "rhctag",
			V:    [10]int32{1, 3},
		},
		Kind:           claircore.SOURCE,
		PackageDB:      "root/buildinfo/Dockerfile-rhdh-rhdh-hub-rhel9-1.3-100",
		RepositoryHint: "rhcc",
		Arch:           "x86_64",
	}

	name2reposData := map[string]map[string][]string{
		"data": {"openshift/ose-logging-elasticsearch6": {"openshift4/ose-logging-elasticsearch6"}},
	}

	type testcase struct {
		Name       string
		Dockerfile string
		Want       []*claircore.Package
	}
	table := []testcase{
		{
			Name:       "Quay",
			Dockerfile: "testdata/Dockerfile-quay-quay-rhel8-v3.5.6-4",
			Want: []*claircore.Package{
				quaySourceContainer,
				{
					Name:    "quay/quay-rhel8",
					Version: "v3.5.6-4",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{3, 5},
					},
					Kind:           claircore.BINARY,
					Source:         quaySourceContainer,
					PackageDB:      "root/buildinfo/Dockerfile-quay-quay-rhel8-v3.5.6-4",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
		{
			Name:       "Clair",
			Dockerfile: "testdata/Dockerfile-quay-clair-rhel8-v3.5.5-4",
			Want: []*claircore.Package{
				clairSourceContainer,
				{
					Name:    "quay/clair-rhel8",
					Version: "v3.5.5-4",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{3, 5},
					},
					Kind:           claircore.BINARY,
					Source:         clairSourceContainer,
					PackageDB:      "root/buildinfo/Dockerfile-quay-clair-rhel8-v3.5.5-4",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
		{
			Name:       "Elasticsearch",
			Dockerfile: "testdata/Dockerfile-openshift-ose-logging-elasticsearch6-v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
			Want: []*claircore.Package{
				loggingSourceContainer,
				{
					Name:    "openshift4/ose-logging-elasticsearch6",
					Version: "v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{4, 6},
					},
					Kind:           claircore.BINARY,
					Source:         loggingSourceContainer,
					PackageDB:      "root/buildinfo/Dockerfile-openshift-ose-logging-elasticsearch6-v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
		{
			Name:       "RHDH",
			Dockerfile: "testdata/Dockerfile-rhdh-rhdh-hub-rhel9-1.3-100",
			Want: []*claircore.Package{
				rhdhSourceContainer,
				{
					Name:    "rhdh/rhdh-hub-rhel9",
					Version: "1.3-100",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{1, 3},
					},
					Kind:           claircore.BINARY,
					Source:         rhdhSourceContainer,
					PackageDB:      "root/buildinfo/Dockerfile-rhdh-rhdh-hub-rhel9-1.3-100",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/container-name-repos-map.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("last-modified", "Mon, 02 Jan 2006 15:04:05 MST")
		if err := json.NewEncoder(w).Encode(name2reposData); err != nil {
			t.Fatal(err)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var cs scanner
	cf := func(v interface{}) error {
		cfg := v.(*ScannerConfig)
		cfg.Name2ReposMappingURL = srv.URL + "/container-name-repos-map.json"
		return nil
	}
	if err := cs.Configure(ctx, cf, srv.Client()); err != nil {
		t.Error(err)
	}

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			mod := test.Modtime(t, tt.Dockerfile)
			a.GenerateLayer(t, tt.Name, mod, func(t testing.TB, w *os.File) {
				dockerfile, err := os.Open(tt.Dockerfile)
				if err != nil {
					t.Fatal(err)
				}
				defer dockerfile.Close()
				fi, err := dockerfile.Stat()
				if err != nil {
					t.Fatal(err)
				}
				tw := tar.NewWriter(w)
				hdr, err := tar.FileInfoHeader(fi, "")
				if err != nil {
					t.Fatal(err)
				}
				hdr.Name = path.Join("root/buildinfo", path.Base(tt.Dockerfile))
				if err := tw.WriteHeader(hdr); err != nil {
					t.Error(err)
				}
				if _, err := io.Copy(tw, dockerfile); err != nil {
					t.Error(err)
				}
				if err := tw.Close(); err != nil {
					t.Error(err)
				}
				t.Logf("wrote tar to: %s", w.Name())
			})

			r := a.Realizer(ctx).(*test.CachedRealizer)
			defer func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
			ls, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{{
				Digest:    "sha256:" + strings.Repeat("beef", 16),
				URI:       "file:" + tt.Name,
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			}})
			if err != nil {
				t.Error(err)
			}

			got, err := cs.Scan(ctx, &ls[0])
			if err != nil {
				t.Error(err)
			}
			t.Logf("found %d packages", len(got))
			if !cmp.Equal(got, tt.Want) {
				t.Error(cmp.Diff(got, tt.Want))
			}
		})
	}
}
