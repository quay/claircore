package rhcc

import (
	"context"
	"encoding/json"
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
	repo := []*claircore.Repository{&GoldRepo}
	repo[0].ID = "1" // Assign it an ID and check it later.
	layerArtifacts := []*indexer.LayerArtifacts{
		{
			Hash: test.RandomSHA256Digest(t),
		},
		{
			Hash: test.RandomSHA256Digest(t),
		},
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: []*claircore.Package{
				{
					ID:             "1",
					Name:           "ubi8",
					Version:        "8.4",
					RepositoryHint: "rhcc",
					Kind:           claircore.BINARY,
					Arch:           "x86_64",
					PackageDB:      "Dockerfile-rhacm",
					Source: &claircore.Package{
						ID:        "3",
						Name:      "ubi8-container",
						Version:   "8.10-1088",
						Kind:      claircore.SOURCE,
						Arch:      "x86_64",
						PackageDB: "Dockerfile-rhacm",
					},
				},
			},
			Repos: repo,
		},
		{
			Hash: test.RandomSHA256Digest(t),
		},
		{
			Hash: test.RandomSHA256Digest(t),
			Pkgs: []*claircore.Package{
				{
					ID:             "2",
					Name:           "rhacm2/acm-grafana-rhel8",
					Version:        "v2.9.5-8",
					RepositoryHint: "rhcc",
					Kind:           claircore.BINARY,
					Arch:           "x86_64",
					PackageDB:      "Dockerfile-rhacm",
					Source: &claircore.Package{
						ID:        "4",
						Name:      "acm-grafana-container",
						Version:   "v2.9.5-8",
						Kind:      claircore.SOURCE,
						Arch:      "x86_64",
						PackageDB: "Dockerfile-rhacm",
					},
				},
			},
			Repos: repo,
		},
		{
			Hash: test.RandomSHA256Digest(t),
		},
	}
	ir, err := coalescer.Coalesce(ctx, layerArtifacts)
	if err != nil {
		t.Fatalf("received error from coalesce method: %v", err)
	}
	report, err := json.MarshalIndent(ir, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal index report: %v", err)
	}
	t.Log(string(report))
	// Check that index report only has the package found in the last layer
	// that has rhcc content.
	if len(ir.Packages) != 2 {
		t.Errorf("expected 1 package, got %d", len(ir.Packages))
	}
	if len(ir.Environments["2"]) != 1 {
		t.Errorf("expected 1 environment, got %d", len(ir.Environments["2"]))
	}
	if len(ir.Environments["2"][0].RepositoryIDs) != 1 {
		t.Errorf("expected 1 repository, got %d", len(ir.Environments["2"][0].RepositoryIDs))
	}
	if ir.Environments["2"][0].RepositoryIDs[0] != "1" {
		t.Errorf("expected repository ID 1, got %s", ir.Environments["2"][0].RepositoryIDs[0])
	}
	if len(ir.Repositories) != 1 {
		t.Errorf("expected 1 repository, got %d", len(ir.Repositories))
	}
	for _, repo := range ir.Repositories {
		if repo.Key != RepositoryKey {
			t.Errorf("expected repository key %s, got %s", RepositoryKey, repo.Key)
		}
	}
}
