package dpkg

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/zlog"
)

func TestDistrolessLayer(t *testing.T) {
	want := []*claircore.Package{
		{
			Name:           "base-files",
			Version:        "11.1+deb11u5",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/base",
			RepositoryHint: "",
		},
		{
			Name:           "netbase",
			Version:        "6.3",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/netbase",
			RepositoryHint: "",
		},
		{
			Name:           "tzdata",
			Version:        "2021a-1+deb11u8",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         nil,
			PackageDB:      "var/lib/dpkg/status.d/tzdata",
			RepositoryHint: "",
		},
	}

	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	tctx, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	hash := claircore.MustParseDigest(`sha256:8fdb1fc20e240e9cae976518305db9f9486caa155fd5fc53e7b3a3285fe8a990`)
	l := claircore.Layer{
		Hash: hash,
	}
	n, err := fetch.Layer(tctx, t, http.DefaultClient, "gcr.io", "distroless/static-debian11", hash)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if err := l.SetLocal(n.Name()); err != nil {
		t.Error(err)
	}

	s := new(DistrolessScanner)
	ps, err := s.Scan(ctx, &l)
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
