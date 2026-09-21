package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/types"
)

// BenchmarkGetOverlappingSource compares one package Get against two packages
// that share a source name. Intern should keep 2Package allocs close to
// 1Package instead of about 2×.
func BenchmarkGetOverlappingSource(b *testing.B) {
	integration.NeedDB(b)
	const descSize = 1024
	desc := strings.Repeat("x", descSize)
	srcKind := types.SourcePackage
	binKind := types.BinaryPackage
	src := &claircore.Package{Name: "kernel", Kind: srcKind}

	for _, n := range []int{1000, 5000} {
		b.Run(strconv.Itoa(n)+"Vulns", func(b *testing.B) {
			ctx := test.Logging(b)
			store := NewMatcherStore(pgtest.TestMatcherDB(ctx, b))
			vulns := make([]*claircore.Vulnerability, n)
			for i := range vulns {
				vulns[i] = &claircore.Vulnerability{
					Updater:     b.Name(),
					Name:        fmt.Sprintf("CVE-%d", i),
					Description: desc,
					Package:     &claircore.Package{Name: "kernel", Kind: srcKind},
				}
			}
			if _, err := store.UpdateVulnerabilities(ctx, b.Name(), driver.Fingerprint(uuid.New().String()), vulns); err != nil {
				b.Fatal(err)
			}
			core := &claircore.IndexRecord{
				Package: &claircore.Package{ID: "core", Name: "kernel-core", Kind: binKind, Source: src},
			}
			mod := &claircore.IndexRecord{
				Package: &claircore.Package{ID: "mod", Name: "kernel-modules", Kind: binKind, Source: src},
			}
			for _, tc := range []struct {
				name    string
				records []*claircore.IndexRecord
			}{
				{"1Package", []*claircore.IndexRecord{core}},
				{"2Package", []*claircore.IndexRecord{core, mod}},
			} {
				b.Run(tc.name, func(b *testing.B) {
					benchGetOverlapping(b, ctx, store, tc.records, n)
				})
			}
		})
	}
}

func benchGetOverlapping(b *testing.B, ctx context.Context, store *MatcherStore, records []*claircore.IndexRecord, n int) {
	b.Helper()
	b.ReportAllocs()
	var got int
	for b.Loop() {
		res, err := store.Get(ctx, records, datastore.GetOpts{})
		if err != nil {
			b.Fatal(err)
		}
		got = 0
		for _, vs := range res {
			got += len(vs)
		}
	}
	if want := n * len(records); got != want {
		b.Fatalf("got %d vulns, want %d", got, want)
	}
}
