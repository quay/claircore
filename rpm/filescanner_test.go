package rpm

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

var testcases = []struct {
	name          string
	expectedFiles int
	ref           test.LayerRef
}{
	{
		name:          "python files",
		expectedFiles: 821,
		ref: test.LayerRef{
			Registry: "registry.access.redhat.com",
			Name:     "ubi9/nodejs-18",
			Digest:   `sha256:1ae06b64755052cef4c32979aded82a18f664c66fa7b50a6d2924afac2849c6e`,
		},
	},
}

func TestFileScannerLayer(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	var s FileScanner
	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			a.LoadLayerFromRegistry(ctx, t, tt.ref)
			r := a.Realizer(ctx).(*test.CachedRealizer)
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			ls, err := r.RealizeDescriptions(ctx, []claircore.LayerDescription{
				{
					Digest:    tt.ref.Digest,
					URI:       "http://example.com",
					MediaType: test.MediaType,
					Headers:   make(map[string][]string),
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			got, err := s.Scan(ctx, &ls[0])
			if err != nil {
				t.Error(err)
			}

			t.Logf("found %d files", len(got))
			if len(got) != tt.expectedFiles {
				t.Fatalf("expected %d files but got %d", tt.expectedFiles, len(got))
			}
			t.Log(got)
		})
	}
}
