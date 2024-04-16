package rhel

import (
	"context"
	"strings"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

var resolverTestcases = []struct {
	name             string
	expectedPackages int
	indexReport      *claircore.IndexReport
}{
	{
		name:             "No files",
		expectedPackages: 2,
		indexReport: &claircore.IndexReport{
			Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
			Packages: map[string]*claircore.Package{
				"123": {
					ID:      "123",
					Name:    "package A",
					Version: "v1.0.0",
					Source: &claircore.Package{
						ID:      "122",
						Name:    "package B source",
						Kind:    claircore.SOURCE,
						Version: "v1.0.0",
					},
					Kind: claircore.BINARY,
				},
				"456": {
					ID:      "456",
					Name:    "package B",
					Version: "v2.0.0",
					Kind:    claircore.BINARY,
				},
			},
			Environments: map[string][]*claircore.Environment{
				"123": {
					{
						PackageDB:      "bdb:var/lib/rpm",
						IntroducedIn:   claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
						RepositoryIDs:  []string{"11"},
						DistributionID: "13",
					},
				},
				"456": {
					{
						PackageDB:     "maven:opt/couchbase/lib/cbas/repo/eventstream-1.0.1.jar",
						IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
						RepositoryIDs: []string{"12"},
					},
				},
			},
			Repositories: map[string]*claircore.Repository{
				"11": {
					ID:   "11",
					Name: "cpe:/a:redhat:rhel_eus:8.6::appstream",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:rhel_eus:8.6:*:appstream:*:*:*:*:*"),
				},
				"12": {
					ID:   "12",
					Name: "maven",
					URI:  "https://repo1.maven.apache.org/maven2",
				},
			},
			Distributions: map[string]*claircore.Distribution{
				"13": {
					ID:         "13",
					DID:        "rhel",
					Name:       "Red Hat Enterprise Linux Server",
					Version:    "7",
					VersionID:  "7",
					CPE:        cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"),
					PrettyName: "Red Hat Enterprise Linux Server 7",
				},
			},
			Success: true,
		},
	},
	{
		name:             "Non-matching files",
		expectedPackages: 2,
		indexReport: &claircore.IndexReport{
			Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
			Packages: map[string]*claircore.Package{
				"123": {
					ID:      "123",
					Name:    "package A",
					Version: "v1.0.0",
					Source: &claircore.Package{
						ID:      "122",
						Name:    "package B source",
						Kind:    claircore.SOURCE,
						Version: "v1.0.0",
					},
					Kind: claircore.BINARY,
				},
				"456": {
					ID:       "456",
					Name:     "package B",
					Version:  "v2.0.0",
					Kind:     claircore.BINARY,
					Filepath: "some/non-rpm-filepath.java",
				},
			},
			Files: map[string][]claircore.File{
				"111": {
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/one.java"},
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/two.java"},
					{Kind: claircore.FileKindRPM, Path: "an/actual/rpm/filepath.java"},
				},
			},
			Environments: map[string][]*claircore.Environment{
				"123": {
					{
						PackageDB:      "bdb:var/lib/rpm",
						IntroducedIn:   claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
						RepositoryIDs:  []string{"11"},
						DistributionID: "13",
					},
				},
				"456": {
					{
						PackageDB:     "maven:opt/couchbase/lib/cbas/repo/eventstream-1.0.1.jar",
						IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
						RepositoryIDs: []string{"12"},
					},
				},
			},
			Repositories: map[string]*claircore.Repository{
				"11": {
					ID:   "11",
					Name: "cpe:/a:redhat:rhel_eus:8.6::appstream",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:rhel_eus:8.6:*:appstream:*:*:*:*:*"),
				},
				"12": {
					ID:   "12",
					Name: "maven",
					URI:  "https://repo1.maven.apache.org/maven2",
				},
			},
			Distributions: map[string]*claircore.Distribution{
				"13": {
					ID:         "13",
					DID:        "rhel",
					Name:       "Red Hat Enterprise Linux Server",
					Version:    "7",
					VersionID:  "7",
					CPE:        cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"),
					PrettyName: "Red Hat Enterprise Linux Server 7",
				},
			},
			Success: true,
		},
	},
	{
		name:             "an RPM and a native JAVA package",
		expectedPackages: 1,
		indexReport: &claircore.IndexReport{
			Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
			Packages: map[string]*claircore.Package{
				"123": {
					ID:      "123",
					Name:    "rpm java package A",
					Version: "v2.0.0-1-1",
					Source: &claircore.Package{
						ID:      "122",
						Name:    "rpm java package A source",
						Kind:    claircore.SOURCE,
						Version: "v2.0.0-1-1",
					},
					Kind:     claircore.BINARY,
					Filepath: "some/rpm/filepath.rpm",
				},
				"456": {
					ID:       "456",
					Name:     "java package A",
					Version:  "v2.0.0",
					Kind:     claircore.BINARY,
					Filepath: "an/actual/rpm/filepath.java",
				},
			},
			Files: map[string][]claircore.File{
				"111": {
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/one.java"},
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/two.java"},
					{Kind: claircore.FileKindRPM, Path: "an/actual/rpm/filepath.java"},
				},
			},
			Environments: map[string][]*claircore.Environment{
				"123": {
					{
						PackageDB:      "bdb:var/lib/rpm",
						IntroducedIn:   claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
						RepositoryIDs:  []string{"11"},
						DistributionID: "13",
					},
				},
				"456": {
					{
						PackageDB:     "maven:opt/couchbase/lib/cbas/repo/eventstream-1.0.1.jar",
						IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
						RepositoryIDs: []string{"12"},
					},
				},
			},
			Repositories: map[string]*claircore.Repository{
				"11": {
					ID:   "11",
					Name: "cpe:/a:redhat:rhel_eus:8.6::appstream",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:rhel_eus:8.6:*:appstream:*:*:*:*:*"),
				},
				"12": {
					ID:   "12",
					Name: "maven",
					URI:  "https://repo1.maven.apache.org/maven2",
				},
			},
			Distributions: map[string]*claircore.Distribution{
				"13": {
					ID:         "13",
					DID:        "rhel",
					Name:       "Red Hat Enterprise Linux Server",
					Version:    "7",
					VersionID:  "7",
					CPE:        cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"),
					PrettyName: "Red Hat Enterprise Linux Server 7",
				},
			},
			Success: true,
		},
	},
	{
		name:             "an RPM and a Java package but wrong file Kind",
		expectedPackages: 2,
		indexReport: &claircore.IndexReport{
			Hash: claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
			Packages: map[string]*claircore.Package{
				"123": {
					ID:      "123",
					Name:    "rpm java package A",
					Version: "v2.0.0-1-1",
					Source: &claircore.Package{
						ID:      "122",
						Name:    "rpm java package A source",
						Kind:    claircore.SOURCE,
						Version: "v2.0.0-1-1",
					},
					Kind:     claircore.BINARY,
					Filepath: "some/rpm/filepath.rpm",
				},
				"456": {
					ID:       "456",
					Name:     "java package A",
					Version:  "v2.0.0",
					Kind:     claircore.BINARY,
					Filepath: "an/actual/rpm/filepath.java",
				},
			},
			Files: map[string][]claircore.File{
				"111": {
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/one.java"},
					{Kind: claircore.FileKindRPM, Path: "some/rpm/filepath/two.java"},
					{Kind: claircore.FileKindWhiteout, Path: "an/actual/rpm/filepath.java"},
				},
			},
			Environments: map[string][]*claircore.Environment{
				"123": {
					{
						PackageDB:      "bdb:var/lib/rpm",
						IntroducedIn:   claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
						RepositoryIDs:  []string{"11"},
						DistributionID: "13",
					},
				},
				"456": {
					{
						PackageDB:     "maven:opt/couchbase/lib/cbas/repo/eventstream-1.0.1.jar",
						IntroducedIn:  claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
						RepositoryIDs: []string{"12"},
					},
				},
			},
			Repositories: map[string]*claircore.Repository{
				"11": {
					ID:   "11",
					Name: "cpe:/a:redhat:rhel_eus:8.6::appstream",
					Key:  repositoryKey,
					CPE:  cpe.MustUnbind("cpe:2.3:a:redhat:rhel_eus:8.6:*:appstream:*:*:*:*:*"),
				},
				"12": {
					ID:   "12",
					Name: "maven",
					URI:  "https://repo1.maven.apache.org/maven2",
				},
			},
			Distributions: map[string]*claircore.Distribution{
				"13": {
					ID:         "13",
					DID:        "rhel",
					Name:       "Red Hat Enterprise Linux Server",
					Version:    "7",
					VersionID:  "7",
					CPE:        cpe.MustUnbind("cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"),
					PrettyName: "Red Hat Enterprise Linux Server 7",
				},
			},
			Success: true,
		},
	},
}

func TestResolver(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	for _, tt := range resolverTestcases {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{}
			ir := r.Resolve(ctx, tt.indexReport, nil)
			if len(ir.Packages) != tt.expectedPackages {
				t.Errorf("expected %d packages but got %d", tt.expectedPackages, len(ir.Packages))
			}
		})
	}
}
