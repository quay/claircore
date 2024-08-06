package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	mock_updater "github.com/quay/claircore/test/mock/updater"
	mock_driver "github.com/quay/claircore/test/mock/updater/driver/v1"
	driver "github.com/quay/claircore/updater/driver/v1"
)

func TestOffline(t *testing.T) {
	ctx := context.Background()
	vs := &driver.ParsedVulnerabilities{
		Updater:       t.Name(),
		Vulnerability: []driver.Vulnerability{{}},
	}
	es := []driver.EnrichmentRecord{
		{
			Enrichment: json.RawMessage("null"),
			Tags:       []string{"a"},
		},
	}
	spool, err := os.CreateTemp(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	t.Run("Fetch", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ctl := gomock.NewController(t)
		n := path.Dir(t.Name())

		upd := mock_driver.NewMockUpdater(ctl)
		upd.EXPECT().
			Name().MinTimes(1).Return(n)
		upd.EXPECT().
			Fetch(matchCtx, matchZip, matchFp, matchClient).DoAndReturn(fetchFunc(t, es, vs))
		fac := mock_driver.NewMockUpdaterFactory(ctl)
		fac.EXPECT().
			Name().MinTimes(1).Return(n)
		fac.EXPECT().
			Create(matchCtx, gomock.Nil()).Times(1).Return([]driver.Updater{upd}, nil)
		store := mock_updater.NewMockStore(ctl)

		u, err := New(ctx, &Options{
			Store:     store,
			Client:    &http.Client{},
			Factories: []driver.UpdaterFactory{fac},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := u.Close(); err != nil {
				t.Error(err)
			}
		}()

		if err := u.Fetch(ctx, nil, spool); err != nil {
			t.Error(err)
		}
	})

	t.Run("Parse", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ctl := gomock.NewController(t)
		n := path.Dir(t.Name())

		upd := mock_driver.NewMockUpdater(ctl)
		upd.EXPECT().
			Name().MinTimes(1).Return(n)
		vp := mock_driver.NewMockVulnerabilityParser(ctl)
		vp.EXPECT().
			ParseVulnerability(matchCtx, matchFS).DoAndReturn(parseVuln)
		ep := mock_driver.NewMockEnrichmentParser(ctl)
		ep.EXPECT().
			ParseEnrichment(matchCtx, matchFS).DoAndReturn(parseEnrich)
		fac := mock_driver.NewMockUpdaterFactory(ctl)
		fac.EXPECT().
			Name().MinTimes(1).Return(n)
		fac.EXPECT().
			Create(matchCtx, gomock.Nil()).Times(1).Return([]driver.Updater{&mockparser{
			Updater:             upd,
			VulnerabilityParser: vp,
			EnrichmentParser:    ep,
		}}, nil)
		store := mock_updater.NewMockStore(ctl)
		store.EXPECT().
			UpdateVulnerabilities(matchCtx, matchUUID, gomock.Eq(n), matchFp, gomock.Eq(vs)).Return(nil)
		store.EXPECT().
			UpdateEnrichments(matchCtx, matchUUID, gomock.Eq(n), matchFp, gomock.Eq(es)).Return(nil)

		u, err := New(ctx, &Options{
			Store:     store,
			Client:    &http.Client{Transport: nil},
			Factories: []driver.UpdaterFactory{fac},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := u.Close(); err != nil {
				t.Error(err)
			}
		}()

		if err := u.Parse(ctx, spool); err != nil {
			t.Error(err)
		}
	})

	t.Run("Prev", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ctl := gomock.NewController(t)
		n := path.Dir(t.Name())
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}

		upd := mock_driver.NewMockUpdater(ctl)
		upd.EXPECT().Name().
			MinTimes(1).
			Return(n)
		upd.EXPECT().Fetch(matchCtx, matchZip, matchFp, matchClient).
			Times(1).
			DoAndReturn(fetchFunc(t, es, vs))
		fac := mock_driver.NewMockUpdaterFactory(ctl)
		fac.EXPECT().Name().
			MinTimes(1).
			Return(n)
		fac.EXPECT().Create(matchCtx, gomock.Nil()).
			Times(1).
			Return([]driver.Updater{upd}, nil)
		store := mock_updater.NewMockStore(ctl)

		u, err := New(ctx, &Options{
			Store:     store,
			Client:    &http.Client{Transport: nil},
			Factories: []driver.UpdaterFactory{fac},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := u.Close(); err != nil {
				t.Error(err)
			}
		}()

		if err := u.Fetch(ctx, spool, io.Discard); err != nil {
			t.Error(err)
		}
	})
}

func TestOpenZip(t *testing.T) {
	// Setup the zip
	n := filepath.Join(t.TempDir(), "zip")
	f, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const comment = `test`
	w := zip.NewWriter(f)
	w.SetComment((url.Values{exportHeader: {comment}}).Encode())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("Stat", func(t *testing.T) {
		f, err := os.Open(n)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		r, c, err := openZip(f)
		if err != nil {
			t.Error(err)
		}
		if got, want := c, comment; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
		if r == nil {
			t.Errorf("%v(%[1]T)", r)
		}
	})
	t.Run("Seek", func(t *testing.T) {
		f, err := os.Open(n)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		rd := struct {
			io.ReaderAt
			io.Seeker
		}{
			ReaderAt: f,
			Seeker:   f,
		}

		r, c, err := openZip(&rd)
		if err != nil {
			t.Error(err)
		}
		if got, want := c, comment; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
		if r == nil {
			t.Errorf("%v(%[1]T)", r)
		}
	})
	t.Run("Size", func(t *testing.T) {
		var buf bytes.Buffer
		f, err := os.Open(n)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := io.Copy(&buf, f); err != nil {
			t.Fatal(err)
		}
		rd := bytes.NewReader(buf.Bytes())

		r, c, err := openZip(rd)
		if err != nil {
			t.Error(err)
		}
		if got, want := c, comment; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}
		if r == nil {
			t.Errorf("%v(%[1]T)", r)
		}
	})
	t.Run("Error", func(t *testing.T) {
		f, err := os.Open(n)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		rd := struct {
			io.ReaderAt
		}{
			ReaderAt: f,
		}

		_, _, err = openZip(&rd)
		t.Log(err)
		if err == nil {
			t.Errorf("got: %v, want: nil", err)
		}
	})
}
