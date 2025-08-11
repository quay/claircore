package suse

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/quay/zlog"
)

func TestFactory(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	u, _ := url.Parse(base)
	f := &Factory{
		c:    http.DefaultClient,
		base: u,
	}
	us, err := f.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(us.Updaters()) == 0 {
		t.Error("expected at least one updater")
	}
	for _, u := range us.Updaters() {
		t.Log(u.Name())
	}
}
