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
	"github.com/quay/claircore/toolkit/types/cpe"
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

func TestGetCPESubstring(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	srcKind := types.SourcePackage
	binKind := types.BinaryPackage
	vuln := func(name, fs string) *claircore.Vulnerability {
		t.Helper()
		mustCPEFS(t, fs)
		return &claircore.Vulnerability{
			Updater: "test-updater",
			Name:    name,
			Package: &claircore.Package{Name: "kernel", Kind: srcKind},
			Repo:    &claircore.Repository{Name: fs, Key: "rhel-cpe-repository"},
		}
	}
	_, err := store.UpdateVulnerabilities(ctx, "test-updater", driver.Fingerprint(uuid.New().String()), []*claircore.Vulnerability{
		vuln("EL8-BASEOS", "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*"),
		vuln("EL8-SHORT", "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"),
		vuln("EL9-BASEOS", "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"),
		vuln("EL9-APPSTREAM", "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*"),
		vuln("EL9-A-SHORT", "cpe:2.3:a:redhat:enterprise_linux:9:*:*:*:*:*:*:*"),
		vuln("EUS-94", "cpe:2.3:o:redhat:rhel_eus:9.4:*:baseos:*:*:*:*:*"),
		vuln("OCP-4", "cpe:2.3:a:redhat:openshift:4:*:*:*:*:*:*:*"),
		vuln("OCP-413-EL8", "cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*"),
		vuln("OCP-3", "cpe:2.3:a:redhat:openshift:3:*:*:*:*:*:*:*"),
		vuln("OCP-AI", "cpe:2.3:a:redhat:openshift_ai:2.16:*:el8:*:*:*:*:*"),
		vuln("AAP", "cpe:2.3:a:redhat:ansible_automation_platform:*:*:*:*:*:*:*:*"),
		vuln("AAP-23", "cpe:2.3:a:redhat:ansible_automation_platform:2.3:*:el8:*:*:*:*:*"),
		vuln("AAP-DEV", "cpe:2.3:a:redhat:ansible_automation_platform_developer:2.3:*:el8:*:*:*:*:*"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	opts := datastore.GetOpts{
		Matchers: []driver.MatchConstraint{driver.PackageModule, driver.RepositoryKey, driver.CPESubstring},
	}
	get := func(fs string) []string {
		t.Helper()
		mustCPEFS(t, fs)
		rec := &claircore.IndexRecord{
			Package: &claircore.Package{
				ID:     "core",
				Name:   "kernel-core",
				Kind:   binKind,
				Source: &claircore.Package{Name: "kernel", Kind: srcKind},
			},
			Repository: &claircore.Repository{
				Key: "rhel-cpe-repository",
				CPE: cpe.MustUnbind(fs),
			},
		}
		res, err := store.Get(ctx, []*claircore.IndexRecord{rec}, opts)
		if err != nil {
			t.Fatalf("get %s: %v", fs, err)
		}
		return vulnNames(res["core"])
	}

	tests := []struct {
		record string
		want   []string
	}{
		{"cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*:*:*:*:*", []string{"EL8-BASEOS", "EL8-SHORT"}},
		{"cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*", []string{"EL9-A-SHORT", "EL9-APPSTREAM"}},
		{"cpe:2.3:a:redhat:openshift:4.13:*:el8:*:*:*:*:*", []string{"OCP-4", "OCP-413-EL8"}},
		{"cpe:2.3:o:redhat:rhel_eus:9.4:*:baseos:*:*:*:*:*", []string{"EUS-94"}},
		{"cpe:2.3:a:redhat:ansible_automation_platform_developer:2.3:*:el8:*:*:*:*:*", []string{"AAP-DEV"}},
		{"cpe:2.3:a:redhat:ansible_automation_platform:2.3:*:el8:*:*:*:*:*", []string{"AAP", "AAP-23"}},
	}
	for _, tt := range tests {
		if diff := cmp.Diff(tt.want, get(tt.record)); diff != "" {
			t.Errorf("%s: %s", tt.record, diff)
		}
	}
}

func TestGetMergesCPESubstringQueriesForSamePackage(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	srcKind := types.SourcePackage
	binKind := types.BinaryPackage
	fs := "cpe:2.3:a:redhat:enterprise_linux:9:*:*:*:*:*:*:*"
	mustCPEFS(t, fs)
	_, err := store.UpdateVulnerabilities(ctx, "test-updater", driver.Fingerprint(uuid.New().String()), []*claircore.Vulnerability{
		{
			Updater: "test-updater",
			Name:    "CVE-2025-11468",
			Package: &claircore.Package{Name: "python3.9", Kind: srcKind},
			Repo:    &claircore.Repository{Name: fs, Key: "rhel-cpe-repository"},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	pkg := func() *claircore.Package {
		return &claircore.Package{
			ID:     "python3",
			Name:   "python3",
			Kind:   binKind,
			Source: &claircore.Package{Name: "python3.9", Kind: srcKind},
		}
	}
	rec := func(fs string) *claircore.IndexRecord {
		t.Helper()
		mustCPEFS(t, fs)
		return &claircore.IndexRecord{
			Package: pkg(),
			Repository: &claircore.Repository{
				Key: "rhel-cpe-repository",
				CPE: cpe.MustUnbind(fs),
			},
		}
	}
	opts := datastore.GetOpts{
		Matchers: []driver.MatchConstraint{driver.PackageModule, driver.RepositoryKey, driver.CPESubstring},
	}

	// UBI9 indexes both a: and o: BaseOS on the same binary. CPESubstring
	// makes those distinct SQL queries; Get used to keep only the last.
	for _, records := range [][]*claircore.IndexRecord{
		{rec("cpe:2.3:a:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"), rec("cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*")},
		{rec("cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"), rec("cpe:2.3:a:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*")},
	} {
		res, err := store.Get(ctx, records, opts)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if diff := cmp.Diff([]string{"CVE-2025-11468"}, vulnNames(res["python3"])); diff != "" {
			t.Fatalf("merged get: %s", diff)
		}
	}
}
