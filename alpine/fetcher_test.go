package alpine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/log"
)

func TestFetcher(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

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
		fi, err := os.Stat(test.serveFile)
		if err != nil {
			t.Error(err)
		}
		tag := fmt.Sprintf(`"%d"`, fi.ModTime().UnixNano())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("if-none-match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("etag", tag)
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
