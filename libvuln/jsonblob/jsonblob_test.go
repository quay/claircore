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

func TestIterationWithBreak(t *testing.T) {
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

	// We will break after getting vulnerabilities.
	test.GenEnrichments(15)
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
		i, iErr := Iterate(io.TeeReader(r, &buf))
		i(func(o *driver.UpdateOperation, i RecordIter) bool {
			i(func(v *claircore.Vulnerability, e *driver.EnrichmentRecord) bool {
				switch o.Kind {
				case driver.VulnerabilityKind:
					got.V = append(got.V, v)
				case driver.EnrichmentKind:
					got.E = append(got.E, *e)
				default:
					t.Errorf("unnexpected kind: %s", o.Kind)
				}
				return true
			})
			// Stop the operation iter, effectively skipping enrichments.
			return false
		})
		return iErr()
	})
	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

func TestIterationWithSkip(t *testing.T) {
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

	// We will skip the updater "skip this".
	test.GenUniqueVulnerabilities(10, "skip this")

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
		i, iErr := Iterate(io.TeeReader(r, &buf))
		i(func(o *driver.UpdateOperation, i RecordIter) bool {
			if o.Updater == "skip this" {
				return true
			}
			i(func(v *claircore.Vulnerability, e *driver.EnrichmentRecord) bool {
				switch o.Kind {
				case driver.VulnerabilityKind:
					got.V = append(got.V, v)
				case driver.EnrichmentKind:
					got.E = append(got.E, *e)
				default:
					t.Errorf("unnexpected kind: %s", o.Kind)
				}
				return true
			})
			return true
		})
		return iErr()
	})
	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
