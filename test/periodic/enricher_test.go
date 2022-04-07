package periodic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libvuln/driver"
)

func TestCVSS(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	e := &cvss.Enricher{}
	err := e.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
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
	for i := 0; i < 5; i++ {
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
