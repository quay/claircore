package rpm

import (
	"context"
	"runtime"
	"testing"
	"unique"
	"weak"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

type FileCheckerFileTestcase struct {
	Name  string
	Owned bool
	Path  string
}

type FileCheckerTestcase struct {
	Name      string
	Layer     test.LayerRef
	Testcases []FileCheckerFileTestcase
}

func (tc *FileCheckerTestcase) Run(ctx context.Context, t *testing.T, a *test.CachedArena) {
	t.Run(tc.Name, func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		a.LoadLayerFromRegistry(ctx, t, tc.Layer)
		r := a.Realizer(ctx).(*test.CachedRealizer)
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})

		rl, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
			{
				Digest:    tc.Layer.Digest,
				URI:       "http://example.com",
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		set, err := NewPathSet(ctx, &rl[0])
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.KeepAlive(set)

		for _, tc := range tc.Testcases {
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()
				ctx := zlog.Test(ctx, t)
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				set, err := NewPathSet(ctx, &rl[0])
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("checking path: %s", tc.Path)
				if got, want := set.Contains(tc.Path), tc.Owned; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
		}
	})
}

func TestIsRPMFile(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	a := test.NewCachedArena(t)

	t.Cleanup(func() {
		t.Log("running GC")
		runtime.GC()
		ct := 0
		pkgCache.m.Range(func(k, v any) bool {
			key := k.(unique.Handle[string])
			t.Logf("%s\tcache entry not removed", key.Value())
			f := v.(weak.Pointer[PathSet])
			if f.Value() != nil {
				t.Errorf("%s\table to upgrade weak pointer", key.Value())
			}
			ct++
			return true
		})
		t.Logf("%d cache entries remaining", ct)
	})

	tcs := []FileCheckerTestcase{
		{
			Name: "nodejs18",
			Layer: test.LayerRef{
				Registry: "registry.access.redhat.com",
				Name:     "ubi9/nodejs-18",
				Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
			},
			Testcases: []FileCheckerFileTestcase{
				{
					Name:  "FoundNode",
					Owned: true,
					Path:  "usr/lib/node_modules/npm/node_modules/safe-buffer/package.json",
				},
				{
					Name:  "FoundPython",
					Owned: true,
					Path:  "usr/lib64/python3.9/site-packages/libcomps-0.1.18-py3.9.egg-info/PKG-INFO",
				},
				{
					Name:  "NotFound",
					Owned: false,
					Path:  "usr/lib/node_modules/npm/node_modules/safe-buffer/package.jsonx",
				},
			},
		},
	}

	for _, tc := range tcs {
		tc.Run(ctx, t, a)
	}
}
