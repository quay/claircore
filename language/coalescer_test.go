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
