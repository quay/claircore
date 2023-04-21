package periodic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
	"github.com/quay/claircore/updater/osv"
)

func TestAWS(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	set, err := aws.UpdaterSet(ctx)
	if err != nil {
		t.Fatal()
	}
	runUpdaterSet(ctx, t, set)
}

func TestAlpine(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	fac, err := alpine.NewFactory(ctx)
	if err != nil {
		t.Fatal()
	}
	err = fac.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
	if err != nil {
		t.Fatal(err)
	}
	set, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestDebian(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	fac, err := debian.NewFactory(ctx)
	if err != nil {
		t.Fatal()
	}
	err = fac.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
	if err != nil {
		t.Fatal(err)
	}
	set, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestOracle(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	set, err := oracle.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestPhoton(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	set, err := photon.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestRHEL(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	fac, err := rhel.NewFactory(ctx, rhel.DefaultManifest)
	if err != nil {
		t.Fatal()
	}
	err = fac.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
	if err != nil {
		t.Fatal(err)
	}
	set, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestSUSE(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	set, err := suse.UpdaterSet(ctx)
	if err != nil {
		t.Fatal()
	}
	runUpdaterSet(ctx, t, set)
}

func TestUbuntu(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	fac, err := ubuntu.NewFactory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = fac.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
	if err != nil {
		t.Fatal(err)
	}
	set, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, set)
}

func TestOSV(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	us, err := osv.Factory.UpdaterSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runUpdaterSet(ctx, t, us)
}

func runUpdaterSet(ctx context.Context, t *testing.T, set driver.UpdaterSet) {
	t.Helper()
	for _, u := range set.Updaters() {
		t.Run(u.Name(), func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			if cfg, ok := u.(driver.Configurable); ok {
				err := cfg.Configure(ctx, func(interface{}) error { return nil }, pkgClient)
				if err != nil {
					t.Fatal(err)
				}
			}
			runUpdater(ctx, t, u)
		})
	}
}

func runUpdater(ctx context.Context, t *testing.T, u driver.Updater) {
	var rc io.ReadCloser
	var nfp driver.Fingerprint
	var err error
	// Debounce any network hiccups.
	for i := 0; i < 5; i++ {
		rc, nfp, err = u.Fetch(ctx, fp)
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

	vs, err := u.Parse(ctx, rc)
	if err != nil {
		t.Error(err)
	}
	t.Logf("reported %d vulnerabilites", len(vs))
}
