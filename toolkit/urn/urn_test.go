package urn

import (
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TODO(hank) Find a conformance test suite and set it up.

func TestString(t *testing.T) {
	tt := []struct {
		In   URN
		Want string
	}{
		{
			In:   URN{NID: "test", NSS: "test"},
			Want: "urn:test:test",
		},
		{
			In: URN{
				NID: "test",
				NSS: "test",
				q:   url.Values{"a": {"b"}}.Encode(),
			},
			Want: "urn:test:test?=a=b",
		},
	}

	for _, tc := range tt {
		got, want := tc.In.String(), tc.Want
		t.Logf("got: %q, want: %q", got, want)
		if got != want {
			t.Fail()
		}
	}
}

func TestParse(t *testing.T) {
	opts := cmp.Options{
		cmp.AllowUnexported(URN{}),
	}
	tt := []struct {
		In   string
		Want URN
	}{
		{
			In: "urn:claircore:test",
			Want: URN{
				NID: "claircore",
				NSS: "test",
			},
		},
		{
			In: "urn:claircore:indexer:package:test?=v=1",
			Want: URN{
				NID: "claircore",
				NSS: "indexer:package:test",
				q:   "v=1",
			},
		},
		{
			In: "urn:claircore:indexer:package:test?+r=1#f",
			Want: URN{
				NID: "claircore",
				NSS: "indexer:package:test",
				r:   "r=1",
				f:   "f",
			},
		},
		{
			In: "urn:test:tes%74",
			Want: URN{
				NID: "test",
				NSS: "tes%74",
			},
		},
		{
			In: "urn:test:%3b",
			Want: URN{
				NID: "test",
				NSS: "%3B",
			},
		},
	}
	for _, tc := range tt {
		t.Logf("parse: %q", tc.In)
		got, err := Parse(tc.In)
		if err != nil {
			t.Errorf("in: %q, error: %v", tc.In, err)
			continue
		}
		want := tc.Want
		t.Logf("got:  %#v %q", got, got.String())
		t.Logf("want: %#v %q", want, want.String())
		// Compare pointers to test RFC 8141 equality.
		if !cmp.Equal(&got, &want) {
			t.Error(cmp.Diff(&got, &want))
		}
		// Compare values to test Go equality.
		if !cmp.Equal(got, want, opts) {
			t.Error(cmp.Diff(got, want, opts))
		}
	}
}

func TestNormalized(t *testing.T) {
	tt := []struct {
		In   string
		Want string
	}{
		{
			In:   "urn:claircore:indexer:package:test?=v=1",
			Want: "urn:claircore:indexer:package:test",
		},
	}
	for _, tc := range tt {
		t.Logf("parse: %q", tc.In)
		got, err := Normalize(tc.In)
		if err != nil {
			t.Errorf("in: %q, error: %v", tc.In, err)
			continue
		}
		want := tc.Want
		t.Logf("got:  %#v", got)
		t.Logf("want: %#v", want)
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
