package alpine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/test"
)

func serveSecDB(t *testing.T) (string, *http.Client) {
	srv := httptest.NewServer(http.FileServer(http.Dir("testdata/fetch")))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

func TestFactory(t *testing.T) {
	ctx := test.Logging(t)

	root, c := serveSecDB(t)
	fac := &Factory{}
	err := fac.Configure(ctx, func(v any) error {
		cf := v.(*FactoryConfig)
		cf.URL = root + "/"
		return nil
	}, c)
	if err != nil {
		t.Fatal(err)
	}
	s, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	us := s.Updaters()
	if len(us) == 0 {
		t.Errorf("expected more than 0 updaters")
	}
	got := make([]string, len(us))
	for i, u := range us {
		got[i] = u.Name()
	}
	want := []string{
		"alpine-community-v3.10-updater",
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
