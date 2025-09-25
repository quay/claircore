package bodhi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestReleases(t *testing.T) {
	const filename = "testdata/releases.json"
	ctx := zlog.Test(context.Background(), t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, pair := range [][2]string{
			{r.Form.Get("rows_per_page"), "100"},
			{r.URL.EscapedPath(), "/releases"},
		} {
			if got, want := pair[0], pair[1]; got != want {
				err := fmt.Sprintf("got: %q, want: %q", got, want)
				t.Error(err)
				http.Error(w, err, http.StatusInternalServerError)
				return
			}
		}
		http.ServeFile(w, r, filename)
	}))
	defer srv.Close()
	var local releases
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&local); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := client{
		Root:   u,
		Client: srv.Client(),
	}
	got, err := c.GetReleases(ctx)
	if err != nil {
		t.Error(err)
	}
	if want := local.Releases; !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
