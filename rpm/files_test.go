package rpm

import (
	"context"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/zlog"
)

var rpmFilesTestcases = []struct {
	name     string
	isRPM    bool
	filePath string
	layer    test.LayerRef
	lenFiles int
}{
	{
		name:     "Found",
		isRPM:    true,
		filePath: "usr/lib/node_modules/npm/node_modules/safe-buffer/package.json",
		layer: test.LayerRef{
			Registry: "registry.access.redhat.com",
			Name:     "ubi9/nodejs-18",
			Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
		},
		lenFiles: 100,
	},
	{
		name:     "Not found",
		isRPM:    false,
		filePath: "usr/lib/node_modules/npm/node_modules/safe-buffer/package.jsonx",
		layer: test.LayerRef{
			Registry: "registry.access.redhat.com",
			Name:     "ubi9/nodejs-18",
			Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
		},
		lenFiles: 100,
	},
}

func TestIsRPMFile(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	a := test.NewCachedArena(t)

	for _, tt := range rpmFilesTestcases {
		t.Run(tt.name, func(t *testing.T) {
			a.LoadLayerFromRegistry(ctx, t, tt.layer)
			r := a.Realizer(ctx).(*test.CachedRealizer)
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})

			realizedLayers, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
				{
					Digest:    tt.layer.Digest,
					URI:       "http://example.com",
					MediaType: test.MediaType,
					Headers:   make(map[string][]string),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			isRPM, err := FileInstalledByRPM(ctx, &realizedLayers[0], tt.filePath)
			if err != nil {
				t.Fatal(err)
			}
			if tt.isRPM != isRPM {
				t.Errorf("expected isRPM: %t, got isRPM: %t", tt.isRPM, isRPM)
			}
		})
	}
}
