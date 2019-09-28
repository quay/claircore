package aws

import (
	"net/http"
	"net/url"
	"testing"

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

		err := client.getMirrors(test)
		assert.NoError(t, err)
	}
}

func Test_Client_RepoMD(t *testing.T) {
	integration.Skip(t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(test)
		assert.NoError(t, err)

		_, err = client.RepoMD()
		assert.NoError(t, err)
	}

}

func Test_Client_Updates(t *testing.T) {
	integration.Skip(t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(test)
		assert.NoError(t, err)

		updates, err := client.Updates()
		assert.NoError(t, err)
		assert.NotEmpty(t, updates.Body)
	}

}
