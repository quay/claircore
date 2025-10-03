package rhel

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/claircore/toolkit/types/cpe"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
)

type CoalescerTestcase struct {
	Name    string
	Fixture func(testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport)
}

func (tc CoalescerTestcase) Run(ctx context.Context, t *testing.T) {
	t.Run(tc.Name, func(t *testing.T) {
		ctx := test.Logging(t, ctx)
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

func TestCoalescer(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

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
					Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
					URI:  "repoid=rhel-8-for-x86_64-baseos-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				repo3 := &claircore.Repository{
					ID:   "3",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
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
						repo3.ID: repo3,
						repo2.ID: repo2,
						repo1.ID: repo1,
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
						want.Environments[k][0].RepositoryIDs = []string{repo1.ID, repo2.ID}
					case 2, 3, 4:
						want.Environments[k][0].RepositoryIDs = []string{repo3.ID}
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
					URI:  "repoid=rhel-8-for-x86_64-baseos-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
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
						repo2.ID: repo2,
						repo1.ID: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg2.ID: {
							{
								PackageDB:     pkg2.PackageDB,
								RepositoryIDs: []string{repo2.ID},
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
					URI:  "repoid=rhel-8-for-x86_64-baseos-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
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
						repo2.ID: repo2,
						repo1.ID: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg1.ID: {
							{
								PackageDB:     pkg1.PackageDB,
								RepositoryIDs: []string{repo2.ID},
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
					URI:  "repoid=rhel-8-for-x86_64-baseos-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
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
						repo2.ID: repo2,
						repo1.ID: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg2.ID: {
							{
								PackageDB:     pkg2.PackageDB,
								RepositoryIDs: []string{repo2.ID},
							},
						},
					},
				}

				return input, want
			},
		},
		{
			Name: "WithDNF",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "hello",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
					RepositoryHint: (url.Values{
						"repoid": {"rhel-8-for-x86_64-appstream-rpms"},
					}).Encode(),
				}
				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1},
					},
				}
				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg1.ID: pkg1},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo1.ID: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg1.ID: {
							{
								PackageDB:     pkg1.PackageDB,
								RepositoryIDs: []string{repo1.ID},
							},
						},
					},
				}
				return input, want
			},
		},
		{
			Name: "WithDNFUnknownRepo",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/a:redhat:enterprise_linux:8::appstream",
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "hello",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
					RepositoryHint: (url.Values{
						"repoid": {"does-not-exist"},
					}).Encode(),
				}
				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1},
					},
				}
				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg1.ID: pkg1},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo1.ID: repo1,
					},
					Environments: map[string][]*claircore.Environment{
						pkg1.ID: {
							{
								PackageDB:     pkg1.PackageDB,
								RepositoryIDs: nil,
							},
						},
					},
				}
				return input, want
			},
		},
		{
			Name: "MultiCPEForOneRepoID",
			Fixture: func(t testing.TB) ([]*indexer.LayerArtifacts, *claircore.IndexReport) {
				repo1 := &claircore.Repository{
					ID:   "1",
					Name: "cpe:/a:redhat:enterprise_linux:8.0::appstream",
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8.0::appstream"),
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				repo2 := &claircore.Repository{
					ID:   "2",
					Name: "cpe:/a:redhat:enterprise_linux:8.1::appstream",
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8.1::appstream"),
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				repo3 := &claircore.Repository{
					ID:   "3",
					Name: "cpe:/a:redhat:enterprise_linux:8.2::appstream",
					CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8.2::appstream"),
					URI:  "repoid=rhel-8-for-x86_64-appstream-rpms",
					Key:  repositoryKey,
				}
				pkg1 := &claircore.Package{
					ID:        "1",
					Name:      "hello",
					Version:   "1.0-1",
					PackageDB: "fixture:/var/lib/rpm",
					RepositoryHint: (url.Values{
						"repoid": {"rhel-8-for-x86_64-appstream-rpms"},
					}).Encode(),
				}
				input := []*indexer.LayerArtifacts{
					{
						Hash:  test.RandomSHA256Digest(t),
						Pkgs:  []*claircore.Package{pkg1},
						Dist:  nil,
						Repos: []*claircore.Repository{repo1, repo2, repo3},
					},
				}
				want := &claircore.IndexReport{
					Hash:          test.RandomSHA256Digest(t),
					Packages:      map[string]*claircore.Package{pkg1.ID: pkg1},
					Distributions: map[string]*claircore.Distribution{},
					Repositories: map[string]*claircore.Repository{
						repo1.ID: repo1,
						repo2.ID: repo2,
						repo3.ID: repo3,
					},
					Environments: map[string][]*claircore.Environment{
						pkg1.ID: {
							{
								PackageDB:     pkg1.PackageDB,
								RepositoryIDs: []string{"1", "2", "3"},
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
