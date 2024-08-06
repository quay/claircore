package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"path"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	mock_updater "github.com/quay/claircore/test/mock/updater"
	mock_driver "github.com/quay/claircore/test/mock/updater/driver/v1"
	"github.com/quay/claircore/updater/driver/v1"
)

func TestNew(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	t.Run("MissingStore", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		u, err := New(ctx, &Options{
			Client: &http.Client{},
		})
		t.Log(err)
		if err == nil {
			t.Error("unexpected success")
			if err := u.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("MissingClient", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		u, err := New(ctx, &Options{
			Store: mock_updater.NewMockStore(nil),
		})
		t.Log(err)
		if err == nil {
			t.Error("unexpected success")
			if err := u.Close(); err != nil {
				t.Error(err)
			}
		}
	})
}

type mockparser struct {
	driver.Updater
	driver.VulnerabilityParser
	driver.EnrichmentParser
}

const (
	vulnerabilityFile = `vulnerability.json`
	enrichmentFile    = `enrichment.json`
)

var (
	matchCtx    = gomock.AssignableToTypeOf(reflect.TypeOf((*context.Context)(nil)).Elem())
	matchFp     = gomock.AssignableToTypeOf(reflect.TypeOf(driver.Fingerprint("")))
	matchZip    = gomock.AssignableToTypeOf(reflect.TypeOf((*zip.Writer)(nil)))
	matchClient = gomock.AssignableToTypeOf(reflect.TypeOf((*http.Client)(nil)))
	matchFS     = gomock.AssignableToTypeOf(reflect.TypeOf((*fs.FS)(nil)).Elem())
	matchUUID   = gomock.AssignableToTypeOf(reflect.TypeOf(uuid.Nil))
)

func fetchFunc(t *testing.T, es []driver.EnrichmentRecord, vs *driver.ParsedVulnerabilities) func(context.Context, *zip.Writer, driver.Fingerprint, *http.Client) (driver.Fingerprint, error) {
	return func(_ context.Context, z *zip.Writer, fp driver.Fingerprint, _ *http.Client) (driver.Fingerprint, error) {
		h := sha256.New()
		var vb, eb bytes.Buffer
		if err := json.NewEncoder(io.MultiWriter(h, &vb)).Encode(vs); err != nil {
			return fp, err
		}
		if err := json.NewEncoder(io.MultiWriter(h, &eb)).Encode(es); err != nil {
			return fp, err
		}
		cfp := driver.Fingerprint(hex.EncodeToString(h.Sum(nil)))
		t.Logf("prev fp: %q", fp)
		t.Logf("calc fp: %q", cfp)
		if fp == cfp {
			return fp, driver.ErrUnchanged
		}

		w, err := z.Create(vulnerabilityFile)
		if err != nil {
			return fp, err
		}
		if _, err := io.Copy(w, &vb); err != nil {
			return fp, err
		}
		w, err = z.Create(enrichmentFile)
		if err != nil {
			return fp, err
		}
		if _, err := io.Copy(w, &eb); err != nil {
			return fp, err
		}
		return cfp, nil
	}
}

func parseVuln(_ context.Context, in fs.FS) (*driver.ParsedVulnerabilities, error) {
	var r driver.ParsedVulnerabilities
	f, err := in.Open(vulnerabilityFile)
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return nil, err
	}
	return &r, f.Close()
}

func parseEnrich(_ context.Context, in fs.FS) (r []driver.EnrichmentRecord, err error) {
	f, err := in.Open(enrichmentFile)
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return nil, err
	}
	return r, f.Close()
}

func TestRun(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ctl := gomock.NewController(t)
	n := path.Base(t.Name())
	vs := &driver.ParsedVulnerabilities{
		Updater:       t.Name(),
		Vulnerability: []driver.Vulnerability{{}},
	}
	es := []driver.EnrichmentRecord{
		{Enrichment: json.RawMessage("null")},
	}

	upd := mock_driver.NewMockUpdater(ctl)
	upd.EXPECT().Name().
		MinTimes(2).
		Return(n)
	upd.EXPECT().Fetch(matchCtx, matchZip, matchFp, matchClient).
		Times(2).
		DoAndReturn(fetchFunc(t, es, vs))
	vp := mock_driver.NewMockVulnerabilityParser(ctl)
	vp.EXPECT().ParseVulnerability(matchCtx, matchFS).
		Times(1).
		DoAndReturn(parseVuln)
	ep := mock_driver.NewMockEnrichmentParser(ctl)
	ep.EXPECT().ParseEnrichment(matchCtx, matchFS).
		Times(1).
		DoAndReturn(parseEnrich)
	fac := mock_driver.NewMockUpdaterFactory(ctl)
	fac.EXPECT().Name().
		MinTimes(2).
		Return(n)
	fac.EXPECT().Create(matchCtx, gomock.Nil()).
		Times(2).
		Return([]driver.Updater{&mockparser{
			Updater:             upd,
			VulnerabilityParser: vp,
			EnrichmentParser:    ep,
		}}, nil)
	store := mock_updater.NewMockStore(ctl)
	var ops []driver.UpdateOperation
	store.EXPECT().UpdateVulnerabilities(matchCtx, matchUUID, gomock.Eq(n), matchFp, gomock.Eq(vs)).
		Times(1).
		DoAndReturn(func(_ context.Context, ref uuid.UUID, name string, fp driver.Fingerprint, _ *driver.ParsedVulnerabilities) error {
			t.Log(fp)
			ops = append(ops, driver.UpdateOperation{
				Fingerprint: fp,
				Updater:     name,
				Kind:        driver.VulnerabilityKind,
				Ref:         ref,
			})
			return nil
		})
	store.EXPECT().UpdateEnrichments(matchCtx, matchUUID, gomock.Eq(n), matchFp, gomock.Eq(es)).
		Times(1).
		DoAndReturn(func(_ context.Context, ref uuid.UUID, name string, fp driver.Fingerprint, _ []driver.EnrichmentRecord) error {
			t.Log(fp)
			ops = append(ops, driver.UpdateOperation{
				Fingerprint: fp,
				Updater:     name,
				Kind:        driver.EnrichmentKind,
				Ref:         ref,
			})
			return nil
		})
	store.EXPECT().GetLatestUpdateOperations(matchCtx).
		Times(2).
		DoAndReturn(func(context.Context) ([]driver.UpdateOperation, error) {
			t.Logf("%#+v", ops)
			return ops, nil
		})

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

	if err := u.Run(ctx, false); err != nil {
		t.Error(err)
	}

	t.Run("Unchanged", func(t *testing.T) {
		if err := u.Run(ctx, false); err != nil {
			t.Error(err)
		}
	})
}
