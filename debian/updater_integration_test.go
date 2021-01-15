package debian

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
			name:    "wheezy",
			release: Wheezy,
		},
		{
			name:    "jessie",
			release: Jessie,
		},
		{
			name:    "stretch",
			release: Stretch,
		},
		{
			name:    "buster",
			release: Buster,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			updater := NewUpdater(table.release)
			t.Log(updater.url)

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
			if got := len(vulns); got < 2 {
				t.Errorf("got: len==%d, want: len>2", got)
			}
		})
	}
}
