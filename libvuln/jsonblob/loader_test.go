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

func TestLoader(t *testing.T) {
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
		l, err := NewLoader(io.TeeReader(r, &buf))
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
