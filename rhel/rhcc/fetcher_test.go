package rhcc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

func TestFetcher(t *testing.T) {
	t.Parallel()
	const serveFile = "testdata/cve-2021-3762.xml"
	ctx := zlog.Test(context.Background(), t)

	fi, err := os.Stat(serveFile)
	if err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprintf(`"%d"`, fi.ModTime().UnixNano())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("if-none-match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("etag", tag)
		http.ServeFile(w, r, serveFile)
	}))
	defer srv.Close()

	u := &updater{
		url:    srv.URL,
		client: srv.Client(),
	}
	rd, hint, err := u.Fetch(ctx, "")
	if err != nil {
		t.Error(err)
	}
	if rd != nil {
		rd.Close()
	}
	_, _, err = u.Fetch(ctx, driver.Fingerprint(hint))
	if got, want := err, driver.Unchanged; got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}
