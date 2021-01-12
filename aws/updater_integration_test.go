package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
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
			assert.NoError(t, err)

			contents, updateHash, err := updater.Fetch(ctx, "")
			assert.NoError(t, err)
			assert.NotEmpty(t, contents)
			assert.NotEmpty(t, updateHash)

			vulns, err := updater.Parse(ctx, contents)
			assert.NoError(t, err)
			assert.NotEmpty(t, vulns)
		})
	}
}
