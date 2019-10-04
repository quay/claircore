package suse

import (
	"context"
	"testing"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func TestLiveDatabase(t *testing.T) {
	integration.Skip(t)
	l := log.TestLogger(t)
	ctx := l.WithContext(context.Background())

	u, err := NewUpdater(EnterpriseServer15)
	if err != nil {
		t.Fatal(err)
	}

	tctx, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	rc, _, err := u.FetchContext(tctx, driver.Fingerprint(""))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	tctx, done = context.WithTimeout(ctx, 8*time.Minute)
	defer done()
	vs, err := u.ParseContext(tctx, rc)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("found %d definitions", len(vs))
}
