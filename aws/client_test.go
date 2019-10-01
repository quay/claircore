package aws

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quay/claircore/test/integration"
	"github.com/stretchr/testify/assert"
)

func Test_Client_GetMirrors(t *testing.T) {
	integration.Skip(t)
	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client := Client{
			c:       &http.Client{},
			mirrors: make([]*url.URL, 0),
		}

		tctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := client.getMirrors(tctx, test)
		assert.NoError(t, err)
	}
}

func Test_Client_RepoMD(t *testing.T) {
	integration.Skip(t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(test)
		assert.NoError(t, err)

		tctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err = client.RepoMD(tctx)
		assert.NoError(t, err)
	}

}

func Test_Client_Updates(t *testing.T) {
	integration.Skip(t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(test)
		assert.NoError(t, err)

		tctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		rc, err := client.Updates(tctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, rc)
	}

}
