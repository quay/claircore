package rhel

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

type CoalescerTestcase struct {
	Name    string
	Fixture func(testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport)
}

func (tc CoalescerTestcase) Run(ctx context.Context, t *testing.T) {
	t.Run(tc.Name, func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		input, want := tc.Fixture(t)
		got, err := new(Coalescer).Coalesce(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		opts := cmp.Options{cmpopts.IgnoreUnexported(claircore.Digest{})}
		if !cmp.Equal(got, want, opts) {
			t.Error(cmp.Diff(got, want, opts))
		}
	})
}

// TestCoalescer tests the private method coalesce on the [Coalescer].
//
// It's simpler to test the core business logic of a [Coalescer] after database
// access would have occurred.
func TestCoalescer(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	tcs := []CoalescerTestcase{
		{
			Name: "Simple",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				pkgs := test.GenUniquePackages(6)
				// Discard dist 0 due to zero value ambiguity.
				dists := test.GenUniqueDistributions(3)
				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:1],
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:2],
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:3],
						Dist:  dists[1:2],
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:4],
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:5],
						Dist:  dists[2:],
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:],
						Dist:  nil,
						Repos: nil,
					},
				}
				want := &claircore.IndexReport{
					Hash:     test.RandomSHA256Digest(t),
					Packages: map[string]*claircore.Package{},
					Distributions: map[string]*claircore.Distribution{
						dists[1].ID: dists[1],
						dists[2].ID: dists[2],
					},
					Repositories: map[string]*claircore.Repository{},
					Environments: map[string][]*claircore.Environment{},
				}
				for i, pkg := range pkgs {
					k := fmt.Sprint(i)
					want.Environments[k] = []*claircore.Environment{
						{
							PackageDB:     fmt.Sprintf("package-db-%d", i),
							RepositoryIDs: []string{},
						},
					}
					switch i {
					case 0, 1, 2, 3:
						want.Environments[k][0].DistributionID = dists[1].ID
					case 4, 5:
						want.Environments[k][0].DistributionID = dists[2].ID
					}
					want.Packages[pkg.ID] = pkg
				}

				return input, want
			},
		},
		{
			Name: "CPERepos",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "rhel-8-for-x86_64-baseos-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				repo3 := &claircore.Repository{
					ID:   "3",
					Name: "rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				pkgs := test.GenUniquePackages(5)
				// Discard dist 0 due to zero value ambiguity.
				dists := test.GenUniqueDistributions(3)

				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:1],
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:2],
						Dist:  nil,
						Repos: []*claircore.Repository{repo1, repo2},
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:3],
						Dist:  dists[1:2],
						Repos: []*claircore.Repository{repo3},
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:4],
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  pkgs[0:5],
						Dist:  dists[2:],
						Repos: nil,
					},
				}

				want := &claircore.IndexReport{
					Hash:     test.RandomSHA256Digest(t),
					Packages: map[string]*claircore.Package{},
					Distributions: map[string]*claircore.Distribution{
						dists[1].ID: dists[1],
						dists[2].ID: dists[2],
					},
					Repositories: map[string]*claircore.Repository{
						repo3.Name: repo3,
						repo1.Name: repo1,
					},
					Environments: map[string][]*claircore.Environment{},
				}
				for i, pkg := range pkgs {
					k := fmt.Sprint(i)
					want.Environments[k] = []*claircore.Environment{
						{
							PackageDB: fmt.Sprintf("package-db-%d", i),
						},
					}
					switch i {
					case 0, 1:
						want.Environments[k][0].RepositoryIDs = []string{repo1.Name, repo2.Name}
					case 2, 3, 4:
						want.Environments[k][0].RepositoryIDs = []string{repo3.Name}
					}
					switch i {
					case 0, 1, 2, 3:
						want.Environments[k][0].DistributionID = dists[1].ID
					case 4:
						want.Environments[k][0].DistributionID = dists[2].ID
					}
					want.Packages[pkg.ID] = pkg
				}

				return input, want
			},
		},
		{
			Name: "UpgradedPackage",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "foo",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}
				pkg2 := &claircore.Package{
					ID:        "2",
					Name:      "foo",
					Version:   "2.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}

				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1},
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  nil,
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg2},
						Dist:  nil,
						Repos: []*claircore.Repository{repo2},
					},
				}

				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg2.ID: pkg2},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo2.Name: repo2,
						repo1.Name: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg2.ID: {
							{
								PackageDB:     pkg2.PackageDB,
								RepositoryIDs: []string{repo2.Name},
							},
						},
					},
				}

				return input, want
			},
		},
		{
			Name: "DowngradedPackage",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "foo",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}
				pkg2 := &claircore.Package{
					ID:        "2",
					Name:      "bar",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}

				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg2},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1},
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  nil,
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo2},
					},
				}

				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg1.ID: pkg1},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo2.Name: repo2,
						repo1.Name: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg1.ID: {
							{
								PackageDB:     pkg1.PackageDB,
								RepositoryIDs: []string{repo2.Name},
							},
						},
					},
				}

				return input, want
			},
		},
		{
			Name: "RemovedPackage",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "foo",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}
				pkg2 := &claircore.Package{
					ID:        "2",
					Name:      "bar",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
				}

				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1},
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  nil,
						Dist:  nil,
						Repos: nil,
					},
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg2},
						Dist:  nil,
						Repos: []*claircore.Repository{repo2},
					},
				}

				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg2.ID: pkg2},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo2.Name: repo2,
						repo1.Name: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg2.ID: {
							{
								PackageDB:     pkg2.PackageDB,
								RepositoryIDs: []string{repo2.Name},
							},
						},
					},
				}

				return input, want
			},
		},
	}

	for _, tc := range tcs {
		tc.Run(ctx, t)
	}
}
