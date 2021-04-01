package bodhi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestFactory(t *testing.T) {
	const filename = "testdata/releases.json"
	ctx := zlog.Test(context.Background(), t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	want := []string{fmt.Sprintf("bodhi/%s", u.Host)}
	sort.Strings(want)
	cf := func(v interface{}) error { v.(*FactoryConfig).API = &srv.URL; return nil }

	fac, err := NewFactory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	us, err := fac.Create(ctx, cf)
	if err != nil {
		t.Error(err)
	}
	got := make([]string, 0, len(want))
	for _, u := range us {
		got = append(got, u.Name())
	}
	sort.Strings(got)

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
