package oracle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore/pkg/ovalutil"
)

func TestUpdaterSetDynamicDiscovery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().Year()

	cases := []struct {
		name      string
		entries   []string
		wantYears []int
		wantErr   bool
	}{
		{
			name: "happy-path-two-years-dedupe-and-filter",
			entries: []string{
				`<a href="com.oracle.elsa-` + strconv.Itoa(now) + `.xml.bz2">com.oracle.elsa-` + strconv.Itoa(now) + `.xml.bz2</a>`,
				`<a href="com.oracle.elsa-` + strconv.Itoa(now-5) + `.xml.bz2">com.oracle.elsa-` + strconv.Itoa(now-5) + `.xml.bz2</a>`,
				`<a href="com.oracle.elsa-` + strconv.Itoa(now-15) + `.xml.bz2">com.oracle.elsa-` + strconv.Itoa(now-15) + `.xml.bz2</a>`,
				`<a href="com.oracle.elsa-` + strconv.Itoa(now) + `.xml.bz2">com.oracle.elsa-` + strconv.Itoa(now) + `.xml.bz2</a>`,
			},
			wantYears: []int{now, now - 5},
		},
		{
			name:      "no-matches",
			entries:   []string{`<a href="unrelated.txt">unrelated.txt</a>`},
			wantYears: nil,
			wantErr:   true,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := `<html><body>` + strings.Join(tt.entries, "\n") + `</body></html>`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			// Configure factory with test URL/client.
			f := &Factory{}
			err := f.Configure(ctx, func(v any) error {
				if cfg, ok := v.(*FactoryConfig); ok {
					cfg.URL = strings.TrimSuffix(srv.URL, "/") + "/"
				}
				return nil
			}, srv.Client())
			if err != nil {
				t.Fatalf("configure: %v", err)
			}

			us, err := f.UpdaterSet(ctx)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UpdaterSet: %v", err)
			}
			ups := us.Updaters()
			if len(ups) != len(tt.wantYears) {
				t.Fatalf("unexpected updater count: got %d want %d", len(ups), len(tt.wantYears))
			}
			want := map[string]bool{}
			for _, y := range tt.wantYears {
				want[strconv.Itoa(y)] = false
			}
			for _, u := range ups {
				up, ok := u.(*Updater)
				if !ok {
					t.Fatalf("unexpected updater type: %T", u)
				}
				n := up.Name()
				parts := strings.Split(n, "-")
				if len(parts) < 3 {
					t.Fatalf("unexpected updater name format: %q", n)
				}
				yr := parts[1]
				if _, ok := want[yr]; !ok {
					t.Fatalf("unexpected year in updater name: %q", n)
				}
				want[yr] = true
				// URL and compression
				base := strings.TrimSuffix(srv.URL, "/") + "/"
				if up.Fetcher.URL == nil {
					t.Fatalf("nil URL for updater %q", n)
				}
				if !strings.HasPrefix(up.Fetcher.URL.String(), base+`com.oracle.elsa-`) ||
					!strings.HasSuffix(up.Fetcher.URL.String(), `.xml.bz2`) {
					t.Fatalf("unexpected URL: %q", up.Fetcher.URL)
				}
				if up.Fetcher.Compression != ovalutil.CompressionBzip2 {
					t.Fatalf("unexpected compression: got %v want %v", up.Fetcher.Compression, ovalutil.CompressionBzip2)
				}
			}
			for yr, ok := range want {
				if !ok {
					t.Fatalf("missing updater for year %s", yr)
				}
			}
		})
	}
}
