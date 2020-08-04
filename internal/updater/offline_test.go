package updater

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/log"
)

type stubUpdater struct{}

var _ driver.Updater = (*stubUpdater)(nil)

func (*stubUpdater) Name() string { return "stub-updater" }

func (*stubUpdater) Fetch(_ context.Context, fp driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	return ioutil.NopCloser(bytes.NewReader(nil)), fp, nil
}

func (*stubUpdater) Parse(_ context.Context, _ io.ReadCloser) ([]*claircore.Vulnerability, error) {
	return nil, nil
}

func TestOfflineRun(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()
	stub := &stubUpdater{}
	f, err := ioutil.TempFile("", "")
	if f != nil {
		defer func() {
			os.Remove(f.Name())
			f.Close()
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan driver.Updater)
	o := Offline{
		Output: f,
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return o.Run(ctx, ch) })
	eg.Go(func() error {
		ch <- stub
		close(ch)
		return nil
	})

	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Error(err)
	}

	if t.Failed() {
		t.FailNow()
	}

	sz := fi.Size()
	t.Logf("reported size: %d", sz)
	if sz == 0 {
		t.Fail()
	}
}
