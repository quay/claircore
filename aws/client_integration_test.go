package aws

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
)

func TestClientIntegrationGetMirrors(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = zlog.Test(ctx, t)
	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client := Client{
			c: &http.Client{},
		}

		err := client.getMirrors(ctx, test.mirrorlist())
		if err != nil {
			t.Error(err)
		}
		t.Log(client.mirrors)
		if len(client.mirrors) == 0 {
			t.Error("wanted at least one mirror")
		}
	}
}

func TestClientRepoMD(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = zlog.Test(ctx, t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(ctx, test)
		if err != nil {
			t.Fatal(err)
		}

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		_, err = client.RepoMD(tctx)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestClientUpdates(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = zlog.Test(ctx, t)

	tests := []Release{Linux1, Linux2}

	for _, test := range tests {
		client, err := NewClient(ctx, test)
		if err != nil {
			t.Fatal(err)
		}

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		rc, err := client.Updates(tctx)
		if err != nil {
			t.Error(err)
		}
		if rc == nil {
			t.Error("got nil io.ReadCloser")
		}
	}
}
