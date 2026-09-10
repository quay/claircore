package language

import (
	"strconv"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
)

func TestCoalescer(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	repoName := "npm"
	coalescer := &coalescer{}
	pkgs := test.GenUniquePackages(6)
	repo := []*claircore.Repository{{
		ID:   "1",
		Name: repoName,
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
	for i := range pkgs[:5] {
		es, ok := ir.Environments[strconv.Itoa(i)]
		if !ok {
			t.Errorf("missing environment for package %d", i)
		}
		e := es[0]
		if len(e.RepositoryIDs) == 0 {
			t.Error("expected some repositories")
		}
		for _, id := range e.RepositoryIDs {
			r := ir.Repositories[id]
			if got, want := r.Name, repoName; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		}
	}
	if _, ok := ir.Environments[strconv.Itoa(5)]; ok {
		t.Error("expected last package to be excluded (no repo in its layer)")
	}
}

func TestCoalescerPackageOverwrite(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	coalescer := &coalescer{}
	repo := []*claircore.Repository{{
		ID:   "1",
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
	if got, want := len(ir.Packages), 1; got != want {
		t.Errorf("got %d packages, want %d", got, want)
	}
	pkg, ok := ir.Packages["1"]
	if !ok {
		t.Error("expected package 1 to exist")
	}
	if got, want := pkg.Version, "7.5.2"; got != want {
		t.Errorf("got version %s, want %s", got, want)
	}
	envs, ok := ir.Environments["1"]
	if !ok {
		t.Error("expected environment for package 1")
	}
	if got, want := len(envs), 1; got != want {
		t.Errorf("got %d environments, want %d", got, want)
	}
	if got, want := envs[0].IntroducedIn.String(), hashes[2].String(); got != want {
		t.Errorf("introduced in %s, want %s", got, want)
	}
}

func TestCoalescerSharedPackageDB(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	coalescer := &coalescer{}
	repo := []*claircore.Repository{{
		ID:   "1",
		Name: "go",
		URI:  "https://pkg.go.dev/",
	}}
	hash := test.RandomSHA256Digest(t)
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash: hash,
			Pkgs: []*claircore.Package{
				{
					ID:        "0",
					Name:      "stdlib",
					Version:   "1.21.0",
					PackageDB: "go:/usr/local/bin/app",
				},
				{
					ID:        "1",
					Name:      "github.com/foo/bar",
					Version:   "v1.2.3",
					PackageDB: "go:/usr/local/bin/app",
				},
				{
					ID:        "2",
					Name:      "github.com/baz/qux",
					Version:   "v0.5.0",
					PackageDB: "go:/usr/local/bin/app",
				},
			},
			Repos: repo,
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	if got, want := len(ir.Packages), 3; got != want {
		t.Errorf("got %d packages, want %d", got, want)
	}
	for _, id := range []string{"0", "1", "2"} {
		if _, ok := ir.Packages[id]; !ok {
			t.Errorf("expected package %s", id)
		}
		if _, ok := ir.Environments[id]; !ok {
			t.Errorf("expected environment for package %s", id)
		}
	}
}
