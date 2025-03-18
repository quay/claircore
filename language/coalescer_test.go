package language

import (
	"context"
	"strconv"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
)

func TestCoalescer(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	coalescer := &coalescer{}
	pkgs := test.GenUniquePackages(6)
	repo := []*claircore.Repository{{
		Name: "npm",
		URI:  "https://www.npmjs.com/",
	}}
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: pkgs[:1],
		},
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: pkgs[:2],
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[:3],
			Repos: repo,
		},
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: pkgs[:4],
		},
		{
			Hash:  test.RandomSHA256Digest(t),
			Pkgs:  pkgs[:5],
			Repos: repo,
		},
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: pkgs,
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	// Expect 0-5 to have gotten associated with the repository.
	for i := range pkgs {
		es, ok := ir.Environments[strconv.Itoa(i)]
		if !ok && i == 5 {
			// Left out the last package.
			continue
		}
		e := es[0]
		if len(e.RepositoryIDs) == 0 {
			t.Error("expected some repositories")
		}
		for _, id := range e.RepositoryIDs {
			r := ir.Repositories[id]
			if got, want := r.Name, "npm"; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		}
	}
}

func TestCoalescerPackageOverwrite(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	coalescer := &coalescer{}
	repo := []*claircore.Repository{{
		Name: "npm",
		URI:  "https://www.npmjs.com/",
	}}
	hashes := []claircore.Digest{
		test.RandomSHA256Digest(t),
		test.RandomSHA256Digest(t),
		test.RandomSHA256Digest(t),
		test.RandomSHA256Digest(t),
	}
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash: hashes[0],
			Pkgs: []*claircore.Package{
				{
					ID:        "0",
					Name:      "semver",
					Version:   "7.3.8",
					PackageDB: "nodejs:usr/local/lib/node_modules/npm/node_modules/semver/package.json",
				},
			},
			Repos: repo,
		},
		{
			Hash: hashes[1],
		},
		{
			Hash: hashes[2],
			Pkgs: []*claircore.Package{
				{
					ID:        "1",
					Name:      "semver",
					Version:   "7.5.2",
					PackageDB: "nodejs:usr/local/lib/node_modules/npm/node_modules/semver/package.json",
				},
			},
			Repos: repo,
		},
		{
			Hash: hashes[3],
			Pkgs: []*claircore.Package{
				{
					ID:        "2",
					Name:      "semver",
					Version:   "7.5.2",
					PackageDB: "nodejs:usr/local/lib/node_modules/npm/node_modules/semver/package.json",
				},
			},
			Repos: repo,
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	if len(ir.Packages) != 1 {
		t.Fatalf("unexpected number of packages: %d != %d", len(ir.Packages), 1)
	}
	pkg, exists := ir.Packages["1"]
	if !exists {
		t.Fatal("expected package does not exist")
	}
	if pkg.Version != "7.5.2" {
		t.Fatalf("unexpected version: %s != %s", pkg.Version, "7.5.2")
	}
	envs, exists := ir.Environments["1"]
	if !exists {
		t.Fatal("expected environments do not exist")
	}
	if len(envs) != 1 {
		t.Fatalf("unexpected number of envionments: %d != %d", len(envs), 1)
	}
	if envs[0].IntroducedIn.String() != hashes[2].String() {
		t.Fatalf("unexpected introducedIn: %s != %s", envs[0].IntroducedIn.String(), hashes[2].String())
	}
}
