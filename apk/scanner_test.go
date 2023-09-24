package apk

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/fetch"
)

func TestScan(t *testing.T) {
	hash, err := claircore.ParseDigest("sha256:89d9c30c1d48bac627e5c6cb0d1ed1eec28e7dbdfbcc04712e4c79c0f83faf17")
	if err != nil {
		t.Fatal(err)
	}
	want := []*claircore.Package{
		{
			Name:           "musl",
			Version:        "1.1.22-r3",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "musl", Version: "1.1.22-r3", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "0c777cf840e82cdc528651e3f3f8f9dda6b1b028",
		},
		{
			Name:           "busybox",
			Version:        "1.30.1-r2",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "busybox", Version: "1.30.1-r2", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "d310e6a3189f51bd55bdc398fca5948c2d044804",
		},
		{
			Name:           "alpine-baselayout",
			Version:        "3.1.2-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "alpine-baselayout", Version: "3.1.2-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "770d8ce7c6c556d952884ad436dd82b17ceb1a9a",
		},
		{
			Name:           "alpine-keys",
			Version:        "2.1-r2",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "alpine-keys", Version: "2.1-r2", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "bdc861e495d33e961b7b9884324bea64a16d2b91",
		},
		{
			Name:           "libcrypto1.1",
			Version:        "1.1.1d-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "openssl", Version: "1.1.1d-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "95e4899bd4d379e6dde69de81fb0506e00322dec",
		},
		{
			Name:           "libssl1.1",
			Version:        "1.1.1d-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "openssl", Version: "1.1.1d-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "95e4899bd4d379e6dde69de81fb0506e00322dec",
		},
		{
			Name:           "ca-certificates-cacert",
			Version:        "20190108-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "ca-certificates", Version: "20190108-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "2e508d7528ca4d9496f05d7f453cbd17dbb80f9d",
		},
		{
			Name:           "libtls-standalone",
			Version:        "2.9.1-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "libtls-standalone", Version: "2.9.1-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "981bf8f8fb3cbbc210ee4f2a2fb5b55d0132e02a",
		},
		{
			Name:           "ssl_client",
			Version:        "1.30.1-r2",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "busybox", Version: "1.30.1-r2", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "d310e6a3189f51bd55bdc398fca5948c2d044804",
		},
		{
			Name:           "zlib",
			Version:        "1.2.11-r1",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "zlib", Version: "1.2.11-r1", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "d2bfb22c8e8f67ad7d8d02704f35ec4d2a19f9b9",
		},
		{
			Name:           "apk-tools",
			Version:        "2.10.4-r2",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "apk-tools", Version: "2.10.4-r2", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "1b98a2fa98c5af24a6a55cc61a4ff1ba1fa1f34f",
		},
		{
			Name:           "scanelf",
			Version:        "1.2.3-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "pax-utils", Version: "1.2.3-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "7768569c07c52f01b11e62e523cd6ddcb4690889",
		},
		{
			Name:           "musl-utils",
			Version:        "1.1.22-r3",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "musl", Version: "1.1.22-r3", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "0c777cf840e82cdc528651e3f3f8f9dda6b1b028",
		},
		{
			Name:           "libc-utils",
			Version:        "0.7.1-r0",
			Kind:           claircore.BINARY,
			Arch:           "x86_64",
			Source:         &claircore.Package{Name: "libc-dev", Version: "0.7.1-r0", Kind: claircore.SOURCE},
			PackageDB:      "lib/apk/db/installed",
			RepositoryHint: "cdca45021830765ad71e58af7ed31f42d1d3d644",
		},
	}

	ctx := zlog.Test(context.Background(), t)
	l := &claircore.Layer{
		Hash: hash,
	}

	n, err := fetch.Layer(ctx, t, http.DefaultClient, "docker.io", "library/alpine", hash)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if err := l.SetLocal(n.Name()); err != nil {
		t.Error(err)
	}

	s := &Scanner{}
	got, err := s.Scan(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d packages", len(got))
	if !cmp.Equal(want, got) {
		t.Fatal(cmp.Diff(want, got))
	}
}
