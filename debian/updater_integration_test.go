package debian

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func Test_Updater(t *testing.T) {
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			updater := NewUpdater(table.release)
			t.Log(updater.url)

			contents, updateHash, err := updater.Fetch(ctx, "")
			assert.NoError(t, err)
			assert.NotEmpty(t, updateHash)

			vulns, err := updater.Parse(ctx, contents)
			assert.NoError(t, err)
			assert.Greater(t, len(vulns), 1)
		})
	}
}
