package oracle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/log"
)

func TestFetch(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "testdata/com.oracle.elsa-2018.xml")
	}))
	u, err := NewUpdater(-1, WithURL(srv.URL, ""))
	if err != nil {
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
