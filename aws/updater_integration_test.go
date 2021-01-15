package aws

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
)

func TestUpdater(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name    string
		release Release
	}{
		{
			name:    "Linux1",
			release: Linux1,
		},
		{
			name:    "Linux2",
			release: Linux2,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)

			updater, err := NewUpdater(table.release)
			if err != nil {
				t.Fatal(err)
			}

			contents, updateHash, err := updater.Fetch(ctx, "")
			if err != nil {
				t.Fatal(err)
			}
			if contents == nil {
				t.Fatal("got nil io.ReadCloser")
			}
			if updateHash == "" {
				t.Fatal("got empty updateHash")
			}

			vulns, err := updater.Parse(ctx, contents)
			if err != nil {
				t.Error(err)
			}
			if len(vulns) == 0 {
				t.Error("no vulns reported")
			}
		})
	}
}
