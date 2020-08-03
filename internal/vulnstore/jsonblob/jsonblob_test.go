package jsonblob

import (
	"context"
	"io"
	"io/ioutil"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
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

	if err := s.Store(ioutil.Discard); err != nil {
		t.Error(err)
	}
}

func TestRoundtrip(t *testing.T) {
	ctx := context.Background()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}

	vs := test.GenUniqueVulnerabilities(10, "test")
	ref, err := a.UpdateVulnerabilities(ctx, "test", "", vs)
	if err != nil {
		t.Error(err)
	}
	t.Logf("ref: %v", ref)

	var got []*claircore.Vulnerability
	r, w := io.Pipe()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { defer w.Close(); return a.Store(w) })
	eg.Go(func() error {
		l, err := Load(ctx, r)
		if err != nil {
			return err
		}
		for l.Next() {
			got = append(got, l.Entry().Vuln...)
		}
		if err := l.Err(); err != nil {
			return err
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Error(err)
	}

	if !cmp.Equal(got, vs) {
		t.Error(cmp.Diff(got, vs))
	}
}
