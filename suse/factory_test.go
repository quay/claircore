package suse

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

func TestFactory(t *testing.T) {
	integration.Skip(t)
	ctx := test.Logging(t)
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
