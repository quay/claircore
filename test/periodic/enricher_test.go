package periodic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

func TestCVSS(t *testing.T) {
	ctx := test.Logging(t)
	e := &cvss.Enricher{}
	err := e.Configure(ctx, func(any) error { return nil }, pkgClient)
	if err != nil {
		t.Fatal(err)
	}
	runEnricher(ctx, t, e)
}

func runEnricher(ctx context.Context, t *testing.T, u driver.EnrichmentUpdater) {
	var rc io.ReadCloser
	var nfp driver.Fingerprint
	var err error
	// Debounce any network hiccups.
	for i := range 5 {
		rc, nfp, err = u.FetchEnrichment(ctx, fp)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After((2 << i) * time.Second):
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log(nfp)
	defer func() {
		if err := rc.Close(); err != nil {
			t.Log(err)
		}
	}()

	ers, err := u.ParseEnrichment(ctx, rc)
	if err != nil {
		t.Error(err)
	}
	t.Logf("reported %d records", len(ers))
}
