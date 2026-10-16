package oracle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

func TestFetch(t *testing.T) {
	ctx := test.Logging(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "testdata/com.oracle.elsa-2018.xml")
	}))
	u, err := NewUpdater(2018, WithURL(srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Configure(ctx, func(_ any) error { return nil }, srv.Client()); err != nil {
		t.Fatal(err)
	}
	rd, hint, err := u.Fetch(ctx, "")
	if err != nil {
		t.Error(err)
	}
	t.Logf("got hint %q", hint)
	if rd != nil {
		rd.Close()
	}

	_, fp, err := u.Fetch(ctx, driver.Fingerprint(hint))
	t.Logf("got hint %q", fp)
	if got, want := err, driver.Unchanged; got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}
