package tarfs_test

// These tests need to be in a separate package in order to prevent a cycle.

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/test/fetch"
)

type seekableTestcase struct {
	Name                string
	Registry, Namespace string
	Layer               claircore.Digest
	Check               []checkFunc
}
type checkFunc func(*testing.T, fs.FS)

func (tc seekableTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		t.Parallel()
		ctx = zlog.Test(ctx, t)
		f, err := fetch.Layer(ctx, t,
			tc.Registry, tc.Namespace, tc.Layer,
			fetch.NoDecompression)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		buf, err := os.Create(filepath.Join(t.TempDir(), filepath.Base(t.Name())))
		if err != nil {
			t.Error(err)
		}
		t.Cleanup(func() {
			if err := buf.Close(); err != nil {
				t.Error(err)
			}
		})

		sys, err := tarfs.New(ctx, f, fi.Size(), buf)
		if err != nil {
			t.Fatal(err)
		}
		defer sys.Close()
		// Do a walk, unconditionally.
		fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Error(err)
			}
			// t.Log(p)
			return nil
		})
		for _, f := range tc.Check {
			f(t, sys)
		}
	}
}

func TestSeekable(t *testing.T) {
	ctx := context.Background()
	t.Parallel()
	for _, tc := range []seekableTestcase{
		{
			Name: "eStargz",
			// layer from docker://ghcr.io/stargz-containers/fedora:30-esgz
			Registry:  "ghcr.io",
			Namespace: "stargz-containers/fedora",
			Layer:     claircore.MustParseDigest(`sha256:a29c6008f8735dd289a374dabb8a277f6bbb8922d921a9c89861794196d6074c`),
			Check: []checkFunc{
				func(t *testing.T, sys fs.FS) {
					b, err := fs.ReadFile(sys, `etc/os-release`)
					if err != nil {
						t.Error(err)
						return
					}
					if !bytes.Contains(b, []byte(`CPE_NAME="cpe:/o:fedoraproject:fedora:30"`)) {
						t.Logf("seemingly garbled contents: %+q", string(b))
						t.Fail()
					}
					t.Log("etc/os-release: OK")
				},
			},
		},
		{
			Name: "zstd:chunked",
			// layer from docker://docker.io/gscrivano/zstd-chunked:fedora
			Registry:  "docker.io",
			Namespace: "gscrivano/zstd-chunked",
			Layer:     claircore.MustParseDigest(`sha256:9970d86e7cb7a3c7ee0a3c8fc2131880b387bc5fe8022a258b456ab2cda4303f`),
			Check: []checkFunc{
				func(t *testing.T, sys fs.FS) {
					b, err := fs.ReadFile(sys, `etc/os-release`)
					if err != nil {
						t.Error(err)
						return
					}
					if !bytes.Contains(b, []byte(`CPE_NAME="cpe:/o:fedoraproject:fedora:35"`)) {
						t.Logf("seemingly garbled contents: %+q", string(b))
						t.Fail()
					}
					t.Log("etc/os-release: OK")
				},
			},
		},
	} {
		t.Run(tc.Name, tc.Run(ctx))
	}
}
