package dpkg

import (
	"archive/tar"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestDistrolessLayer(t *testing.T) {
	tt := []struct {
		name string
		ref  test.LayerRef
		want []*claircore.Package
	}{
		{
			name: "debian11",
			ref: test.LayerRef{
				Registry: "gcr.io",
				Name:     "distroless/static-debian11",
				Digest:   `sha256:8fdb1fc20e240e9cae976518305db9f9486caa155fd5fc53e7b3a3285fe8a990`,
			},
			want: []*claircore.Package{
				{
					Name:      "base-files",
					Version:   "11.1+deb11u5",
					Kind:      types.BinaryPackage,
					Arch:      "amd64",
					PackageDB: "var/lib/dpkg/status.d/base",
				},
				{
					Name:      "netbase",
					Version:   "6.3",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/netbase",
				},
				{
					Name:      "tzdata",
					Version:   "2021a-1+deb11u8",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/tzdata",
				},
			},
		},
		{
			name: "debian12",
			ref: test.LayerRef{
				Registry: "gcr.io",
				Name:     "distroless/static-debian12",
				Digest:   `sha256:ef49c20a7b35aa995683f311510d35d77e203a2204f84de14a71a6d726e6af73`,
			},
			want: []*claircore.Package{
				{
					Name:      "tzdata",
					Version:   "2025b-0+deb12u2",
					Kind:      types.BinaryPackage,
					Arch:      "all",
					PackageDB: "var/lib/dpkg/status.d/tzdata",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := test.Logging(t)
			l := test.RealizeLayer(ctx, t, tc.ref)
			var s DistrolessScanner

			ps, err := s.Scan(ctx, l)
			if err != nil {
				t.Error(err)
			}
			if got, want := len(ps), len(tc.want); got != want {
				t.Errorf("checking length, got: %d, want: %d", got, want)
			}

			if !cmp.Equal(ps, tc.want) {
				t.Fatal(cmp.Diff(ps, tc.want))
			}
		})
	}
}

func TestDistrolessMissingListFile(t *testing.T) {
	t.Parallel()
	mod := test.Modtime(t, "distroless_scanner_test.go")
	layerfile := test.GenerateFixture(t, "distroless-missing-list.tar", mod, missingListSetup)
	ctx := test.Logging(t)
	var l claircore.Layer
	var s DistrolessScanner

	f, err := os.Open(layerfile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := l.Init(ctx, &test.AnyDescription, f); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	ps, err := s.Scan(ctx, &l)
	if err != nil {
		t.Fatalf("scan should not fail with missing .list file: %v", err)
	}
	if got := len(ps); got != 1 {
		t.Fatalf("got %d packages, want 1", got)
	}
	if ps[0].Name != "gcc-14-base" {
		t.Errorf("got package name %q, want %q", ps[0].Name, "gcc-14-base")
	}
}

func missingListSetup(t testing.TB, f *os.File) {
	w := tar.NewWriter(f)
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, dir := range []string{
		"var/lib/dpkg/",
		"var/lib/dpkg/status.d/",
	} {
		if err := w.WriteHeader(&tar.Header{
			Name: dir,
		}); err != nil {
			t.Fatal(err)
		}
	}
	const controlData = "Package: gcc-14-base\nVersion: 14.2.0-19\nArchitecture: amd64\nSource: gcc-14\n\n"
	if err := w.WriteHeader(&tar.Header{
		Name: "var/lib/dpkg/status.d/gcc-14-base",
		Size: int64(len(controlData)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(controlData)); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "var/lib/dpkg/status.d/gcc-14-base.list",
		Linkname: "../info/gcc-14-base.list",
	}); err != nil {
		t.Fatal(err)
	}
}
