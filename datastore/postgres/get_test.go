package postgres

import (
	"encoding/binary"
	"slices"
	"testing"
	"unique"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/types"
)

func TestDecodeInt8(t *testing.T) {
	var bin [8]byte
	binary.BigEndian.PutUint64(bin[:], 42)

	t.Run("text", func(t *testing.T) {
		got, err := decodeInt8([]byte("42"), pgx.TextFormatCode)
		if err != nil {
			t.Fatal(err)
		}
		if got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	})
	t.Run("binary", func(t *testing.T) {
		got, err := decodeInt8(bin[:], pgx.BinaryFormatCode)
		if err != nil {
			t.Fatal(err)
		}
		if got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	})
	t.Run("binary short", func(t *testing.T) {
		if _, err := decodeInt8(bin[:4], pgx.BinaryFormatCode); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("text bad", func(t *testing.T) {
		if _, err := decodeInt8([]byte("x"), pgx.TextFormatCode); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestGetInternsOverlappingRows(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	srcKind := types.SourcePackage
	binKind := types.BinaryPackage
	_, err := store.UpdateVulnerabilities(ctx, "test-updater", driver.Fingerprint(uuid.New().String()), []*claircore.Vulnerability{
		{
			Updater: "test-updater",
			Name:    "CVE-SRC",
			Package: &claircore.Package{Name: "kernel", Kind: srcKind},
		},
		{
			Updater: "test-updater",
			Name:    "CVE-CORE",
			Package: &claircore.Package{Name: "kernel-core", Kind: binKind},
		},
		{
			Updater: "test-updater",
			Name:    "CVE-MOD",
			Package: &claircore.Package{Name: "kernel-modules", Kind: binKind},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	src := &claircore.Package{Name: "kernel", Kind: srcKind}
	res, err := store.Get(ctx, []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				ID:     "core",
				Name:   "kernel-core",
				Kind:   binKind,
				Source: src,
			},
		},
		{
			Package: &claircore.Package{
				ID:     "mod",
				Name:   "kernel-modules",
				Kind:   binKind,
				Source: src,
			},
		},
	}, datastore.GetOpts{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if diff := cmp.Diff([]string{"CVE-CORE", "CVE-SRC"}, vulnNames(res["core"])); diff != "" {
		t.Fatalf("kernel-core: %s", diff)
	}
	if diff := cmp.Diff([]string{"CVE-MOD", "CVE-SRC"}, vulnNames(res["mod"])); diff != "" {
		t.Fatalf("kernel-modules: %s", diff)
	}

	srcCore := vulnByName(res["core"], "CVE-SRC")
	srcMod := vulnByName(res["mod"], "CVE-SRC")
	if srcCore == nil || srcMod == nil {
		t.Fatal("missing interned source vuln")
	}
	if srcCore != srcMod {
		t.Fatal("expected interned source vuln to be the same pointer")
	}
}

func TestGetPopulatesAliases(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	srcKind := types.SourcePackage
	binKind := types.BinaryPackage
	wantSelf := claircore.Alias{Space: unique.Make("CVE"), Name: "CVE-SRC"}
	wantAlias := claircore.Alias{Space: unique.Make("GHSA"), Name: "GHSA-kernel"}
	_, err := store.UpdateVulnerabilities(ctx, "test-updater", driver.Fingerprint(uuid.New().String()), []*claircore.Vulnerability{
		{
			Updater: "test-updater",
			Name:    "CVE-SRC",
			Package: &claircore.Package{Name: "kernel", Kind: srcKind},
			Self:    wantSelf,
			Aliases: []claircore.Alias{wantAlias},
		},
		{
			Updater: "test-updater",
			Name:    "CVE-CORE",
			Package: &claircore.Package{Name: "kernel-core", Kind: binKind},
		},
		{
			Updater: "test-updater",
			Name:    "CVE-MOD",
			Package: &claircore.Package{Name: "kernel-modules", Kind: binKind},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	src := &claircore.Package{Name: "kernel", Kind: srcKind}
	res, err := store.Get(ctx, []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				ID:     "core",
				Name:   "kernel-core",
				Kind:   binKind,
				Source: src,
			},
		},
		{
			Package: &claircore.Package{
				ID:     "mod",
				Name:   "kernel-modules",
				Kind:   binKind,
				Source: src,
			},
		},
	}, datastore.GetOpts{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	srcCore := vulnByName(res["core"], "CVE-SRC")
	srcMod := vulnByName(res["mod"], "CVE-SRC")
	if srcCore == nil || srcMod == nil {
		t.Fatal("missing source vuln")
	}
	if srcCore != srcMod {
		t.Fatal("expected source vuln to be the same pointer")
	}
	if !srcCore.Self.Equal(wantSelf) {
		t.Fatalf("self: got %s, want %s", srcCore.Self, wantSelf)
	}
	if len(srcCore.Aliases) != 1 || !srcCore.Aliases[0].Equal(wantAlias) {
		t.Fatalf("aliases: got %v, want [%s]", srcCore.Aliases, wantAlias)
	}
	if core := vulnByName(res["core"], "CVE-CORE"); core == nil || core.Self.Valid() || len(core.Aliases) != 0 {
		t.Fatalf("CVE-CORE should have no aliases: %+v", core)
	}
}

func vulnNames(vs []*claircore.Vulnerability) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Name)
	}
	slices.Sort(out)
	return out
}

func vulnByName(vs []*claircore.Vulnerability, name string) *claircore.Vulnerability {
	for _, v := range vs {
		if v.Name == name {
			return v
		}
	}
	return nil
}
