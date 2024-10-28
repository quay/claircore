package suse

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestFactory(t *testing.T) {
	ctx := context.Background()
	u, _ := url.Parse("https://ftp.suse.com/pub/projects/security/oval/")
	f := &Factory{
		c:    http.DefaultClient,
		base: u,
	}
	us, err := f.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range us.Updaters() {
		t.Log(u.Name())
	}
}
