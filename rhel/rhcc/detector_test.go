package rhcc

import (
	"archive/tar"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestPackageDetector(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

	type testcase struct {
		Name       string
		LabelsFile string
		LabelsPath string
		Want       []*claircore.Package
	}
	table := []testcase{
		{
			Name:       "PackageLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "root/buildinfo/labels.json",
			Want: []*claircore.Package{
				{
					Name:    "openshift-gitops-1/gitops-rhel8-operator",
					Version: "1744596866",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{1744596866},
					},
					Kind:           claircore.SOURCE,
					PackageDB:      "root/buildinfo/labels.json",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
				{
					Name:    "openshift-gitops-1/gitops-rhel8-operator",
					Version: "1744596866",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{1744596866},
					},
					Kind: claircore.BINARY,
					Source: &claircore.Package{
						Name:    "openshift-gitops-1/gitops-rhel8-operator",
						Version: "1744596866",
						NormalizedVersion: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{1744596866},
						},
						Kind:           claircore.SOURCE,
						PackageDB:      "root/buildinfo/labels.json",
						RepositoryHint: "rhcc",
						Arch:           "x86_64",
					},
					PackageDB:      "root/buildinfo/labels.json",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
		{
			Name:       "PackageRHCOSLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "usr/share/buildinfo/labels.json",
			Want: []*claircore.Package{
				{
					Name:    "openshift-gitops-1/gitops-rhel8-operator",
					Version: "1744596866",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{1744596866},
					},
					Kind:           claircore.SOURCE,
					PackageDB:      "usr/share/buildinfo/labels.json",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
				{
					Name:    "openshift-gitops-1/gitops-rhel8-operator",
					Version: "1744596866",
					NormalizedVersion: claircore.Version{
						Kind: "rhctag",
						V:    [10]int32{1744596866},
					},
					Kind: claircore.BINARY,
					Source: &claircore.Package{
						Name:    "openshift-gitops-1/gitops-rhel8-operator",
						Version: "1744596866",
						NormalizedVersion: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{1744596866},
						},
						Kind:           claircore.SOURCE,
						PackageDB:      "usr/share/buildinfo/labels.json",
						RepositoryHint: "rhcc",
						Arch:           "x86_64",
					},
					PackageDB:      "usr/share/buildinfo/labels.json",
					RepositoryHint: "rhcc",
					Arch:           "x86_64",
				},
			},
		},
		{
			Name:       "PackageBadPathLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "bad/path/labels.json",
			Want:       nil,
		},
	}
	var cd detector

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := test.Logging(t)
			mod := test.Modtime(t, tt.LabelsFile)
			a.GenerateLayer(t, tt.Name, mod, genLayerFunc(tt.LabelsFile, tt.LabelsPath))

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

			got, err := cd.Scan(ctx, &ls[0])
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

func TestRepositoryDetector(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

	type testcase struct {
		Name       string
		LabelsFile string
		LabelsPath string
		Want       []*claircore.Repository
	}
	table := []testcase{
		{
			Name:       "RepositoryLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "root/buildinfo/labels.json",
			Want: []*claircore.Repository{
				{
					Name: "cpe:2.3:a:redhat:openshift_gitops:1.16:*:el8:*:*:*:*:*",
					Key:  "rhcc-container-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:openshift_gitops:1.16:*:el8:*:*:*:*:*"),
				},
			},
		},
		{
			Name:       "RepositoryRHCOSLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "usr/share/buildinfo/labels.json",
			Want: []*claircore.Repository{
				{
					Name: "cpe:2.3:a:redhat:openshift_gitops:1.16:*:el8:*:*:*:*:*",
					Key:  "rhcc-container-repository",
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:openshift_gitops:1.16:*:el8:*:*:*:*:*"),
				},
			},
		},
		{
			Name:       "RepositoryBadLabelsTest",
			LabelsFile: "testdata/simple_labels.json",
			LabelsPath: "bad/path/labels.json",
			Want:       nil,
		},
	}
	var cd repoDetector

	opt := cmp.Comparer(func(src, tgt cpe.WFN) bool {
		return cpe.Compare(src, tgt).IsEqual()
	})

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := test.Logging(t)
			mod := test.Modtime(t, tt.LabelsFile)
			a.GenerateLayer(t, tt.Name, mod, genLayerFunc(tt.LabelsFile, tt.LabelsPath))

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

			got, err := cd.Scan(ctx, &ls[0])
			if err != nil {
				t.Error(err)
			}
			t.Logf("found %d repositories", len(got))
			if !cmp.Equal(got, tt.Want, opt) {
				t.Error(cmp.Diff(got, tt.Want, opt))
			}
		})
	}
}

func genLayerFunc(path string, imgPath string) func(t testing.TB, w *os.File) {
	return func(t testing.TB, w *os.File) {
		dockerfile, err := os.Open(path)
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
		hdr.Name = imgPath
		if err := tw.WriteHeader(hdr); err != nil {
			t.Error(err)
		}
		if _, err := io.Copy(tw, dockerfile); err != nil {
			t.Error(err)
		}
		if err := tw.Close(); err != nil {
			t.Error(err)
		}
	}
}
