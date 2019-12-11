package aws

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/test/integration"
)

func Test_Client_Linux1_Integration_GetMirrors(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client := Client{
			c: &http.Client{},
		}

		err := client.getMirrors(ctx, test)
		assert.NoError(t, err)
		assert.NotEmpty(t, client.mirrors)
		t.Log(client.mirrors)
	}
}
