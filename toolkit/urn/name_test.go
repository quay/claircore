package urn

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestName(t *testing.T) {
	version := "1"
	tt := []struct {
		In   string
		Want Name
	}{
		// Weird cases first:
		{
			In: "urn:claircore:indexer:package:test?=version=1&version=999",
			Want: Name{
				System:  "indexer",
				Kind:    "package",
				Name:    "test",
				Version: &version,
			},
		},
		{
			In: "urn:claircore:indexer:package:test",
			Want: Name{
				System: "indexer",
				Kind:   "package",
				Name:   "test",
			},
		},
		{
			In: "urn:claircore:indexer:package:test?+resolve=something",
			Want: Name{
				System: "indexer",
				Kind:   "package",
				Name:   "test",
			},
		},
		{
			In: "urn:claircore:indexer:package:test#some_anchor",
			Want: Name{
				System: "indexer",
				Kind:   "package",
				Name:   "test",
			},
		},

		// Some other exhaustive cases:
		{
			In: "urn:claircore:indexer:repository:test?=version=1",
			Want: Name{
				System:  "indexer",
				Kind:    "repository",
				Name:    "test",
				Version: &version,
			},
		},
		{
			In: "urn:claircore:indexer:distribution:test?=version=1",
			Want: Name{
				System:  "indexer",
				Kind:    "distribution",
				Name:    "test",
				Version: &version,
			},
		},
		{
			In: "urn:claircore:matcher:vulnerability:test?=version=1",
			Want: Name{
				System:  "matcher",
				Kind:    "vulnerability",
				Name:    "test",
				Version: &version,
			},
		},
		{
			In: "urn:claircore:matcher:enrichment:test?=version=1",
			Want: Name{
				System:  "matcher",
				Kind:    "enrichment",
				Name:    "test",
				Version: &version,
			},
		},
	}

	for _, tc := range tt {
		t.Logf("parse: %q", tc.In)
		u, err := Parse(tc.In)
		if err != nil {
			t.Error(err)
			continue
		}
		got, err := u.Name()
		if err != nil {
			t.Error(err)
			continue
		}
		want := tc.Want
		t.Logf("name:  %q", got.String())
		if !cmp.Equal(&got, &want) {
			t.Error(cmp.Diff(&got, &want))
		}
	}
}
