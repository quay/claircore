package jsonblob

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

func TestStore(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	vs := test.GenUniqueVulnerabilities(10, "test")
	ref, err := s.UpdateVulnerabilities(ctx, "test", "", vs)
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	var buf bytes.Buffer
	if err := s.Store(&buf); err != nil {
		t.Error(err)
	}
	t.Logf("wrote:\n%s", buf.String())
}

func TestRoundtrip(t *testing.T) {
	ctx := context.Background()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}

	var want, got struct {
		V []*claircore.Vulnerability
		E []driver.EnrichmentRecord
	}

	want.V = test.GenUniqueVulnerabilities(10, "test")
	ref, err := a.UpdateVulnerabilities(ctx, "test", "", want.V)
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	want.E = test.GenEnrichments(15)
	ref, err = a.UpdateEnrichments(ctx, "test", "", want.E)
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	var buf bytes.Buffer
	defer func() {
		t.Logf("wrote:\n%s", buf.String())
	}()
	r, w := io.Pipe()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { defer w.Close(); return a.Store(w) })
	eg.Go(func() error {
		l, err := Load(ctx, io.TeeReader(r, &buf))
		if err != nil {
			return err
		}
		for l.Next() {
			e := l.Entry()
			if e.Vuln != nil && e.Enrichment != nil {
				t.Error("expecting entry to have either vulnerability or enrichment, got both")
			}
			if e.Vuln != nil {
				got.V = append(got.V, l.Entry().Vuln...)
			}
			if e.Enrichment != nil {
				got.E = append(got.E, l.Entry().Enrichment...)
			}
		}
		if err := l.Err(); err != nil {
			return err
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

func TestEnrichments(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	en := test.GenEnrichments(5)
	ref, err := s.UpdateEnrichments(ctx, "test", "", en)
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	var buf bytes.Buffer
	if err := s.Store(&buf); err != nil {
		t.Error(err)
	}
	t.Logf("wrote:\n%s", buf.String())
}

func TestDeltaUpdaters(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	numVulns := 10
	vs := test.GenUniqueVulnerabilities(numVulns, "test")
	ref, err := s.DeltaUpdateVulnerabilities(ctx, "test", "", vs, []string{})
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	var buf bytes.Buffer
	if err := s.Store(&buf); err != nil {
		t.Error(err)
	}
	t.Logf("wrote:\n%s", buf.String())
	lnCt := 0
	for _, err := buf.ReadBytes('\n'); err == nil; _, err = buf.ReadBytes('\n') {
		lnCt++
	}
	if lnCt != numVulns {
		t.Errorf("expected %d vulns but got %d", numVulns, lnCt)
	}
}
