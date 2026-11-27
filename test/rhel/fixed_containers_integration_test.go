//go:build integration

package rhel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/rhel/vex"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestFixedBuildBoundaryDatabase(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "rhel", "vex", "testdata", "cve-2025-68121-fixed-containers.json"))
	if err != nil {
		t.Fatal(err)
	}
	for fixture, tc := range map[string]struct {
		data     []byte
		versions map[string]struct {
			version, product string
			affected, fixed  bool
		}
	}{
		"timestamp": {data, map[string]struct {
			version, product string
			affected, fixed  bool
		}{
			"before":        {"1775604308", "redhat:openshift:4.19", true, false},
			"at":            {"1775604309", "redhat:openshift:4.19", false, true},
			"after":         {"1793816697", "redhat:openshift:4.19", false, true},
			"other product": {"1793816697", "example:unrelated_product:1", false, false},
		}},
		"versioned tag": {[]byte(strings.ReplaceAll(string(data), "1775604309", "v4.19.0-10")), map[string]struct {
			version, product string
			affected, fixed  bool
		}{
			"before":              {"v4.19.0-9", "redhat:openshift:4.19", true, false},
			"at":                  {"v4.19.0-10", "redhat:openshift:4.19", false, true},
			"after":               {"v4.19.2-20", "redhat:openshift:4.19", false, true},
			"next minor same CPE": {"v4.20.0-20", "redhat:openshift:4.19", false, false},
		}},
	} {
		t.Run(fixture, func(t *testing.T) {
			integration.NeedDB(t)
			ctx := context.Background()
			pool := pgtest.TestMatcherDB(ctx, t)
			store := postgres.NewMatcherStore(pool)
			rules, err := vex.NewParser().Parse(ctx, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.UpdateVulnerabilities(ctx, "rhel-vex", driver.Fingerprint(fixture), rules); err != nil {
				t.Fatal(err)
			}
			for name, vc := range tc.versions {
				t.Run(name, func(t *testing.T) {
					v, err := rhctag.Parse(vc.version)
					if err != nil {
						t.Fatal(err)
					}
					ir := &claircore.IndexReport{
						Packages:     map[string]*claircore.Package{},
						Repositories: map[string]*claircore.Repository{"rh": {ID: "rh", Key: rhcc.RepositoryKey, CPE: cpe.MustUnbind("cpe:/a:" + vc.product + "::el9")}},
						Environments: map[string][]*claircore.Environment{},
					}
					ir.Repositories["rh"].Name = ir.Repositories["rh"].CPE.String()
					for id, kind := range map[string]types.PackageKind{"image": types.BinaryPackage, "ancestry": types.AncestryPackage} {
						ir.Packages[id] = &claircore.Package{ID: id, Name: "openshift4/ose-olm-operator-controller-rhel9", Version: vc.version, Kind: kind, Source: &claircore.Package{}, NormalizedVersion: v.Version(true)}
						ir.Environments[id] = []*claircore.Environment{{RepositoryIDs: []string{"rh"}}}
					}
					r, err := matcher.EnrichedMatch(ctx, ir, []driver.Matcher{rhcc.Matcher}, nil, store)
					if err != nil {
						t.Fatal(err)
					}
					affected := len(r.PackageVulnerabilities["image"]) > 0
					fixed := len(r.PackageNotVulnerable["ancestry"]) > 0
					if affected != vc.affected || fixed != vc.fixed {
						t.Errorf("affected=%v fixed=%v, want %v/%v", affected, fixed, vc.affected, vc.fixed)
					}
				})
			}
		})
	}
}
