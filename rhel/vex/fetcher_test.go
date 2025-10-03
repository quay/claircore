package vex

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/klauspost/compress/snappy"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/csaf"
)

func TestFactory(t *testing.T) {
	ctx := test.Logging(t)
	root, c := ServeSecDB(t, "testdata/server.txtar")
	fac := &Factory{}
	err := fac.Configure(ctx, func(v any) error {
		cf := v.(*FactoryConfig)
		cf.URL = root + "/"
		return nil
	}, c)
	if err != nil {
		t.Fatal(err)
	}

	s, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	if len(s.Updaters()) != 1 {
		t.Errorf("expected 1 updater in the updaterset but got %d", len(s.Updaters()))
	}
	data, fp, err := s.Updaters()[0].Fetch(ctx, "")
	if err != nil {
		t.Fatalf("error Fetching, cannot continue: %v", err)
	}
	defer data.Close()
	// Check fingerprint.
	f, err := parseFingerprint(fp)
	if err != nil {
		t.Errorf("fingerprint cannot be parsed: %v", err)
	}
	if f.changesEtag != "something" {
		t.Errorf("bad etag for the changes.csv endpoint: %s", f.changesEtag)
	}
	if f.deletionsEtag != "somethingelse" {
		t.Errorf("bad etag for the deletions.csv endpoint: %s", f.deletionsEtag)
	}

	// Check saved vulns
	expectedLnCt := 7
	lnCt := 0
	r := bufio.NewReader(snappy.NewReader(data))
	for b, err := r.ReadBytes('\n'); err == nil; b, err = r.ReadBytes('\n') {
		_, err := csaf.Parse(bytes.NewReader(b))
		if err != nil {
			t.Error(err)
		}
		lnCt++
	}
	if lnCt != expectedLnCt {
		t.Errorf("got %d entries but expected %d", lnCt, expectedLnCt)
	}

	newData, newFP, err := s.Updaters()[0].Fetch(ctx, driver.Fingerprint(f.String()))
	if err != nil {
		t.Fatalf("error re-Fetching, cannot continue: %v", err)
	}
	defer newData.Close()

	f, err = parseFingerprint(newFP)
	if err != nil {
		t.Errorf("fingerprint cannot be parsed: %v", err)
	}
	if f.changesEtag != "something" {
		t.Errorf("bad etag for the changes.csv endpoint: %s", f.changesEtag)
	}
	if f.deletionsEtag != "somethingelse" {
		t.Errorf("bad etag for the deletions.csv endpoint: %s", f.deletionsEtag)
	}

	r = bufio.NewReader(snappy.NewReader(newData))
	for _, err := r.ReadBytes('\n'); err == nil; _, err = r.ReadBytes('\n') {
		t.Fatal("should not have anymore data")
	}
}
