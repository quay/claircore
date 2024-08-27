package nodejs_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/nodejs"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestScanLocal(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()

	table := []struct {
		name      string
		want      []*claircore.Package
		layerPath string
	}{
		{
			name: "sample NodeJS app",
			want: []*claircore.Package{
				{
					Name:    "accepts",
					Version: "1.3.8",
				},
				{
					Name:    "array-flatten",
					Version: "1.1.1",
				},
				{
					Name:    "express",
					Version: "4.18.2",
				},
				{
					Name:    "ipaddr.js",
					Version: "1.9.1",
				},
			},
			layerPath: "testdata/sample-nodejs-app.tar",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.Open(tt.layerPath)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			ctx := zlog.Test(ctx, t)
			scanner := &nodejs.Scanner{}
			var l claircore.Layer
			err = l.Init(ctx, &claircore.LayerDescription{
				Digest:    "sha256:1e1bb6832aca0391eefafc58fd9a6b77d728eab3195c536562a86f15b06aed92",
				MediaType: `application/vnd.oci.image.layer.v1.tar`,
			}, file)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			got, err := scanner.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(len(got), 57) {
				t.Error(cmp.Diff(len(got), 57))
			}

			gotMap := make(map[string]*claircore.Package, len(got))
			for _, g := range got {
				gotMap[g.Name] = g
			}

			// Test a select few packages.
			for _, w := range tt.want {
				g, exists := gotMap[w.Name]
				if !exists {
					t.Error(fmt.Sprintf("%s was not found", w.Name))
					continue
				}

				// Only compare name and version at this time.
				p := &claircore.Package{
					Name:    g.Name,
					Version: g.Version,
				}
				if !cmp.Equal(p, w) {
					t.Error(cmp.Diff(p, w))
				}
			}
		})
	}
}
