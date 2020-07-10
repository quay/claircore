package photon

import (
	"context"
	"testing"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func check_release(t *testing.T, photon_release Release) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

	u, err := NewUpdater(photon_release)
	if err != nil {
		t.Fatal(err)
	}

	tctx, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	rc, _, err := u.Fetch(tctx, driver.Fingerprint(""))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	tctx, done = context.WithTimeout(ctx, 8*time.Minute)
	defer done()
	vs, err := u.Parse(tctx, rc)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s: found %d definitions", photon_release, len(vs))
}

func TestLiveDatabase(t *testing.T) {
	integration.Skip(t)
	check_release(t, Photon1)
	check_release(t, Photon2)
	check_release(t, Photon3)
}
