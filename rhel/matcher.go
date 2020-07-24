package rhel

import (
	"context"
	"net/http"
	"os"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel/repo2cpe"
)

// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red Hat
const DefaultRepo2CPEMappingURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

// Matcher implements driver.Matcher.
type Matcher struct {
	mapping *repo2cpe.RepoCPEMapping
}

var _ driver.Matcher = (*Matcher)(nil)

// TODO: we need to plumb a context thru here
func NewMatcher(ctx context.Context, client *http.Client) *Matcher {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/matcher/NewMatcher").
		Logger()

	mappingURL := os.Getenv("REPO_TO_CPE_URL")
	if mappingURL == "" {
		mappingURL = DefaultRepo2CPEMappingURL
	}
	if client == nil {
		client = http.DefaultClient
	}

	// launch local updater
	log.Info().Msg("launching local updater job")
	localUpdater := repo2cpe.NewLocalUpdaterJob(mappingURL, client)

	// blocks until the first update try as an attempt to have a
	// mapping file present before constructor returns.
	localUpdater.Start(ctx)

	return &Matcher{
		&repo2cpe.RepoCPEMapping{
			RepoCPEUpdater: localUpdater,
		},
	}
}

// Name implements driver.Matcher.
func (*Matcher) Name() string {
	return "rhel"
}

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == RedHatRepositoryKey
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.PackageModule,
	}
}

// Vulnerable implements driver.Matcher.
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	pkgVer, vulnVer := version.NewVersion(record.Package.Version), version.NewVersion(vuln.Package.Version)
	// Assume the vulnerability record we have is for the last known vulnerable
	// version, so greater versions aren't vulnerable.
	cmp := func(i int) bool { return i != version.GREATER }
	// But if it's explicitly marked as a fixed-in version, it't only vulnerable
	// if less than that version.
	if vuln.FixedInVersion != "" {
		vulnVer = version.NewVersion(vuln.FixedInVersion)
		cmp = func(i int) bool { return i == version.LESS }
	}
	// compare version and architecture
	match := cmp(pkgVer.Compare(vulnVer)) && vuln.ArchOperation.Cmp(record.Package.Arch, vuln.Package.Arch)
	if !match {
		return false, nil
	}

	// translate content-sets into CPEs and check whether given vulnerability has same CPE
	repoCPEs, err := m.mapping.RepositoryToCPE(ctx, []string{record.Repository.Name})
	if err != nil {
		return false, err
	}
	_, found := find(repoCPEs, vuln.Repo.Name)
	return found, nil
}

func find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}
