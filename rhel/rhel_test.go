package rhel

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/zlog"
)

func TestGetContentManifest(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	tests := []struct {
		name    string
		tarPath string
		want    *contentManifest
		wantNil bool
		wantErr bool
	}{
		{
			name:    "WithDNFHintTrue",
			tarPath: "testdata/layer-dnf-hint-true.tar",
			want: &contentManifest{
				ContentSets: []string{"content-set-1", "content-set-2"},
				FromDNFHint: true,
			},
		},
		{
			name:    "NoFromDNFHintField_DefaultsToContentSets",
			tarPath: "testdata/layer-with-embedded-cs.tar",
			want: &contentManifest{
				ContentSets: []string{"content-set-1", "content-set-2"},
				FromDNFHint: false, // default value when field doesn't exist
			},
		},
		{
			name:    "NoContentManifest",
			tarPath: "testdata/layer-with-no-cpe-info.tar",
			wantNil: true,
		},
		{
			name:    "InvalidJSON",
			tarPath: "testdata/layer-with-invalid-content-manifests-json.tar",
			wantNil: true, // graceful degradation for syntax errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)

			// Create a layer from the test data
			f, err := os.Open(tt.tarPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    `sha256:` + strings.Repeat(`beef`, 16),
				URI:       `file:///dev/null`,
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			}
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})

			sys, err := l.FS()
			if err != nil {
				t.Fatal(err)
			}

			got, err := getContentManifest(ctx, sys)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil but got %+v", got)
				}
				return
			}

			if !cmp.Equal(got, tt.want) {
				t.Error(cmp.Diff(got, tt.want))
			}
		})
	}
}
