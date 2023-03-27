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
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestContainerScanner(t *testing.T) {
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
	name2reposData := map[string]map[string][]string{
		"data": {"openshift/ose-logging-elasticsearch6": {"openshift4/ose-logging-elasticsearch6"}},
	}

	table := []struct {
		dockerfile string
		want       []*claircore.Package
	}{
		{
			dockerfile: ".testdata/Dockerfile-quay-quay-rhel8-v3.5.6-4",
			want: []*claircore.Package{
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
			dockerfile: ".testdata/Dockerfile-quay-clair-rhel8-v3.5.5-4",
			want: []*claircore.Package{
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
			dockerfile: ".testdata/Dockerfile-openshift-ose-logging-elasticsearch6-v4.6.0-202112132021.p0.g2a13a81.assembly.stream",
			want: []*claircore.Package{
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
	}
	ctx := zlog.Test(context.Background(), t)
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

	for _, tt := range table {
		t.Run(tt.dockerfile, func(t *testing.T) {
			dockerfile, err := os.Open(tt.dockerfile)
			if err != nil {
				t.Fatal(err)
			}
			defer dockerfile.Close()
			fi, err := dockerfile.Stat()
			if err != nil {
				t.Fatal(err)
			}
			tmpdir := t.TempDir()
			// Write a tarball with the binary.
			tarname := filepath.Join(tmpdir, "tar")
			tf, err := os.Create(tarname)
			if err != nil {
				t.Fatal(err)
			}
			defer tf.Close()
			tw := tar.NewWriter(tf)
			hdr, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				t.Fatal(err)
			}
			hdr.Name = path.Join("root/buildinfo", path.Base(tt.dockerfile))
			if err := tw.WriteHeader(hdr); err != nil {
				t.Error(err)
			}
			if _, err := io.Copy(tw, dockerfile); err != nil {
				t.Error(err)
			}
			if err := tw.Close(); err != nil {
				t.Error(err)
			}
			t.Logf("wrote tar to: %s", tf.Name())

			// Make a fake layer with the tarball.
			l := claircore.Layer{}
			l.SetLocal(tf.Name())

			got, err := cs.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			t.Logf("found %d packages", len(got))
			if !cmp.Equal(got, tt.want) {
				t.Error(cmp.Diff(got, tt.want))
			}
		})
	}
}
