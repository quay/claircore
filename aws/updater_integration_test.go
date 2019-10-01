package aws

import (
	"testing"

	"github.com/quay/claircore/test/integration"
	"github.com/stretchr/testify/assert"
)

func Test_Updater(t *testing.T) {
	integration.Skip(t)
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
			updater, err := NewUpdater(table.release)
			assert.NoError(t, err)

			contents, updateHash, err := updater.Fetch()
			assert.NoError(t, err)
			assert.NotEmpty(t, contents)
			assert.NotEmpty(t, updateHash)

			vulns, err := updater.Parse(contents)
			assert.NoError(t, err)
			assert.NotEmpty(t, vulns)
		})
	}
}
