package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore/test/integration"
)

func Test_Client_Linux1_GetMirrors(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tests := []struct {
		release  Release
		expected []string
	}{
		{
			release: Linux1,
			expected: []string{
				"http://packages.us-west-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.us-west-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.us-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-southeast-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-northeast-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-northeast-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.eu-west-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.eu-central-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.sa-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-southeast-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "testdata/mirrors_linux1.txt")
	}))
	defer srv.Close()

	// send requests to test server
	tmp := amazonLinux1Mirrors
	amazonLinux1Mirrors = srv.URL
	defer func() {
		amazonLinux1Mirrors = tmp
	}()

	for _, test := range tests {
		client := Client{
			c:       srv.Client(),
			mirrors: make([]*url.URL, 0),
		}

		urls := []*url.URL{}
		for _, s := range test.expected {
			u, err := url.Parse(s)
			assert.NoError(t, err)
			urls = append(urls, u)
		}

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		err := client.getMirrors(tctx, test.release)
		assert.NoError(t, err)
		assert.ElementsMatch(t, urls, client.mirrors)
		t.Log(client.mirrors)
	}
}

func Test_Client_Linux2_GetMirrors(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tests := []struct {
		release  Release
		expected []string
	}{
		{
			release: Linux2,
			expected: []string{
				"https://cdn.amazonlinux.com/2/core/2.0/x86_64/221a4af09d96ac4e34202cc7bdfa252410419542548cc685dc86ed1c17ca4204",
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "testdata/mirrors_linux2.txt")
	}))
	defer srv.Close()

	// send requests to test server
	tmp := amazonLinux2Mirrors
	amazonLinux2Mirrors = srv.URL
	defer func() {
		amazonLinux2Mirrors = tmp
	}()

	for _, test := range tests {
		client := Client{
			c:       srv.Client(),
			mirrors: make([]*url.URL, 0),
		}

		urls := []*url.URL{}
		for _, s := range test.expected {
			u, err := url.Parse(s)
			assert.NoError(t, err)
			urls = append(urls, u)
		}

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		err := client.getMirrors(tctx, test.release)
		assert.NoError(t, err)
		assert.ElementsMatch(t, urls, client.mirrors)
		t.Log(client.mirrors)
	}
}

func Test_Client_RepoMD(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(ctx, test)
		assert.NoError(t, err)

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		_, err = client.RepoMD(tctx)
		assert.NoError(t, err)
	}

}

func Test_Client_Updates(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(ctx, test)
		assert.NoError(t, err)

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		rc, err := client.Updates(tctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, rc)
	}
}
