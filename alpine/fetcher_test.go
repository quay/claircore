package alpine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/log"
)

func TestFetcher(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)

	var table = []struct {
		release   Release
		repo      Repo
		serveFile string
	}{
		{
			release:   V3_10,
			repo:      Community,
			serveFile: "testdata/v3_10_community_truncated.yaml",
		},
	}

	for _, test := range table {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, test.serveFile)
		}))

		u, err := NewUpdater(test.release, test.repo, WithURL(srv.URL))

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
}
