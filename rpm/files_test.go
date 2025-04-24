package rpm

import (
	"context"
	"fmt"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

var (
	cache = map[string]map[string]struct{}{}
	refs  = map[string]int{}

	testFileCache = &filesCache{
		c:    cache,
		refs: refs,
	}
)

var rpmFilesTestcases = []struct {
	name     string
	isRPM    bool
	filePath string
}{
	{
		name:     "Found Node",
		isRPM:    true,
		filePath: "usr/lib/node_modules/npm/node_modules/safe-buffer/package.json",
	},
	{
		name:     "Found Python",
		isRPM:    true,
		filePath: "usr/lib64/python3.9/site-packages/libcomps-0.1.18-py3.9.egg-info/PKG-INFO",
	},
	{
		name:     "Not found",
		isRPM:    false,
		filePath: "usr/lib/node_modules/npm/node_modules/safe-buffer/package.jsonx",
	},
}

func TestIsRPMFile(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	a := test.NewCachedArena(t)
	fc = testFileCache
	layer := test.LayerRef{
		Registry: "registry.access.redhat.com",
		Name:     "ubi9/nodejs-18",
		Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
	}
	a.LoadLayerFromRegistry(ctx, t, layer)
	r := a.Realizer(ctx).(*test.CachedRealizer)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		fc.wg.Wait() // Wait for all goroutines to finish
		err := checkCleanup(fc)
		if err != nil {
			t.Error(err)
		}
	})

	realizedLayers, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
		{
			Digest:    layer.Digest,
			URI:       "http://example.com",
			MediaType: test.MediaType,
			Headers:   make(map[string][]string),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range rpmFilesTestcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(zlog.Test(context.Background(), t))
			t.Parallel()
			fc, err := NewFileChecker(ctx, &realizedLayers[0])
			if err != nil {
				t.Fatal(err)
			}
			isRPM := fc.IsRPM(tt.filePath)
			if tt.isRPM != isRPM {
				t.Errorf("expected isRPM: %t, got isRPM: %t", tt.isRPM, isRPM)
			}
			cancel()
		})
	}
}

func checkCleanup(fc *filesCache) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(cache) > 0 {
		return fmt.Errorf("cache is left unclean after a second: %d items left", len(cache))
	}
	if len(refs) > 0 {
		return fmt.Errorf("refs left unclean after a second: %d items left", len(refs))
	}
	return nil
}
