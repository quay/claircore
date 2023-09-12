package rhcc

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
	for _, p := range pkgs {
		// Mark them as if they came from this package's package scanner
		p.RepositoryHint = `rhcc`
	}
	repo := []*claircore.Repository{&goldRepo}
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
			if got, want := r.Name, goldRepo.Name; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		}
	}
}
