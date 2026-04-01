package dpkg

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestDistrolessLayer(t *testing.T) {
	ctx := test.Logging(t)
	want := []*claircore.Package{
		{
			Name:           "base-files",
			Version:        "11.1+deb11u5",
			Kind:           types.BinaryPackage,
			Arch:           "amd64",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/base",
			RepositoryHint: "",
		},
		{
			Name:           "netbase",
			Version:        "6.3",
			Kind:           types.BinaryPackage,
			Arch:           "all",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/netbase",
			RepositoryHint: "",
		},
		{
			Name:           "tzdata",
			Version:        "2021a-1+deb11u8",
			Kind:           types.BinaryPackage,
			Arch:           "all",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/tzdata",
			RepositoryHint: "",
		},
	}
	l := test.RealizeLayer(ctx, t, test.LayerRef{
		Registry: "gcr.io",
		Name:     "distroless/static-debian11",
		Digest:   `sha256:8fdb1fc20e240e9cae976518305db9f9486caa155fd5fc53e7b3a3285fe8a990`,
	})
	var s DistrolessScanner

	t.Parallel()
	ps, err := s.Scan(ctx, l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(ps), 3; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}

	if !cmp.Equal(ps, want) {
		t.Fatal(cmp.Diff(ps, want))
	}
}

func TestDistrolessMissingListFile(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Build a tar with:
	// - var/lib/dpkg/status.d/gcc-14-base (valid control file)
	// - var/lib/dpkg/status.d/gcc-14-base.list (symlink to missing ../info/gcc-14-base.list)
	controlData := []byte("Package: gcc-14-base\nVersion: 14.2.0-19\nArchitecture: amd64\nSource: gcc-14\n\n")
	buf := &bytes.Buffer{}
	h := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(buf, h))

	for _, dir := range []string{
		"var/lib/dpkg/",
		"var/lib/dpkg/status.d/",
	} {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     dir,
			Mode:     0755,
			ModTime:  now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "var/lib/dpkg/status.d/gcc-14-base",
		Size:     int64(len(controlData)),
		Mode:     0644,
		ModTime:  now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(controlData); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "var/lib/dpkg/status.d/gcc-14-base.list",
		Linkname: "../info/gcc-14-base.list",
		Mode:     0644,
		ModTime:  now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	desc := claircore.LayerDescription{
		URI:       "file:///dev/null",
		Digest:    fmt.Sprintf("sha256:%x", h.Sum(nil)),
		MediaType: "application/vnd.oci.image.layer.v1.tar",
	}
	var l claircore.Layer
	if err := l.Init(ctx, &desc, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	var s DistrolessScanner
	ps, err := s.Scan(ctx, &l)
	if err != nil {
		t.Fatalf("scan should not fail with missing .list file: %v", err)
	}

	// Should still find the valid package.
	if got := len(ps); got != 1 {
		t.Fatalf("got %d packages, want 1", got)
	}
	if ps[0].Name != "gcc-14-base" {
		t.Errorf("got package name %q, want %q", ps[0].Name, "gcc-14-base")
	}
}
