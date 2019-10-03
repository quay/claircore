package aws

import (
	"context"
	"log"
	"net/http"
	"testing"

	"github.com/quay/claircore/test/integration"
	"github.com/stretchr/testify/assert"
)

func Test_Client_Linux1_Integration_GetMirrors(t *testing.T) {
	integration.Skip(t)
	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client := Client{
			c: &http.Client{},
		}

		err := client.getMirrors(context.Background(), test)
		assert.NoError(t, err)
		assert.NotEmpty(t, client.mirrors)
		log.Printf("%v", client.mirrors)
		log.Printf("%v", len(client.mirrors))
	}
}
