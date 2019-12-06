package ubuntu

import (
	"context"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/test/integration"
)

func Test_Updater(t *testing.T) {
	integration.Skip(t)
	var tt = []struct {
		name    string
		release Release
	}{
		{
			name:    "artful",
			release: Artful,
		},
		{
			name:    "bionic",
			release: Bionic,
		},
		{
			name:    "cosmic",
			release: Cosmic,
		},
		{
			name:    "disco",
			release: Disco,
		},
		{
			name:    "precise",
			release: Precise,
		},
		{
			name:    "trusty",
			release: Trusty,
		},
		{
			name:    "xenial",
			release: Xenial,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			updater := NewUpdater(table.release)
			log.Printf("%v", updater.url)

			contents, updateHash, err := updater.Fetch(context.Background(), "")
			assert.NoError(t, err)
			assert.NotEmpty(t, updateHash)

			vulns, err := updater.Parse(context.Background(), contents)
			assert.NoError(t, err)
			assert.Greater(t, len(vulns), 1)

		})
	}

}
