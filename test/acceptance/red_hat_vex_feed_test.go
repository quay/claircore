package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	testpostgres "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/fixtures"
)

type vexFeedTest struct {
	Name    string
	Image   string
	VEXURLs []string
	Expect  []fixtures.ManifestRecord
}

// internalVEXTests contains claircore's internal VEX feed test cases.
// These test both the current and beta Red Hat VEX feeds against known images.
//
// CVEs tested:
//   - CVE-2023-4911: glibc (Looney Tunables)
//   - CVE-2023-2650: openssl
//   - CVE-2023-38545: curl (beta feed only - current feed CPEs don't match UBI9)
//   - CVE-2026-6846, CVE-2026-3441, CVE-2026-4647, CVE-2026-6844, CVE-2026-3442,
//     CVE-2026-25679, CVE-2026-31790, CVE-2025-69644
var internalVEXTests = []vexFeedTest{
	// Current feed tests - vulnerable image (ubi9:9.0.0)
	{
		Name:  "UBI9_90_Vulnerable_CurrentFeed",
		Image: "registry.access.redhat.com/ubi9:9.0.0",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-2650.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "BaseOS-9.2.0.Z.MAIN.EUS:glibc-0:2.34-60.el9_2.7.aarch64", Status: fixtures.StatusAffected},
			{ID: "CVE-2023-2650", Product: "BaseOS-9.2.0.Z.MAIN.EUS:openssl-libs-1:3.0.7-16.el9_2.aarch64", Status: fixtures.StatusAffected},
		},
	},
	// Current feed tests - patched image (ubi9:9.3)
	{
		Name:  "UBI9_93_Patched_CurrentFeed",
		Image: "registry.access.redhat.com/ubi9:9.3",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-2650.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "BaseOS-9.2.0.Z.MAIN.EUS:glibc-0:2.34-60.el9_2.7.aarch64", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-2650", Product: "BaseOS-9.2.0.Z.MAIN.EUS:openssl-libs-1:3.0.7-16.el9_2.aarch64", Status: fixtures.StatusAbsent},
		},
	},
	// Beta feed tests - vulnerable image (ubi9:9.0.0)
	{
		Name:  "UBI9_90_Vulnerable_BetaFeed",
		Image: "registry.access.redhat.com/ubi9:9.0.0",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-2650.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-38545.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "rhel-9.3.0:glibc.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2023-2650", Product: "rhel-9.3.0:openssl.src", Status: fixtures.StatusAffected},
			// CVE-2023-38545 (curl) is patched in 9.0.0, so it should be absent.
			// The beta feed incorrectly reports it as affected (false positive).
			{ID: "CVE-2023-38545", Product: "rhel-9.3.0:curl.src", Status: fixtures.StatusAbsent},
		},
	},
	// Beta feed tests - patched (non-vulnerable) image (ubi9:9.3)
	// NOTE: All CVEs below are expected to FAIL because the beta feed incorrectly
	// marks patched packages as known_affected. This documents the data quality issue.
	{
		Name:  "UBI9_93_Patched_BetaFeed",
		Image: "registry.access.redhat.com/ubi9:9.3",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-2650.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-38545.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "rhel-9.3.0:glibc.src", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-2650", Product: "rhel-9.3.0:openssl.src", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-38545", Product: "rhel-9.3.0:curl.src", Status: fixtures.StatusAbsent},
		},
	},
	// Beta feed tests - hummingbird go image.
	// The beta feed includes hummingbird products; the current feed uses "red_hat_hardened_images".
	// NOTE: CVE-2026-25679 (golang) diverges between feeds: the beta feed marks golang1.25 as
	// "fixed" (hummingbird-1:golang1.25-0:1.25.9-1.hum1), while the current feed marks it as
	// "known_affected". The installed version equals the fixedIn version, so the package is not
	// reported as vulnerable - correctly absent from results.
	{
		Name:  "Hummingbird_BetaFeed",
		Image: "quay.io/hummingbird/go@sha256:4bb8023430f26cfb4e779319a83d5d9577ce54fbf6433e9340e0035ab33b5ccc",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-6846.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-3441.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-25679.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-4647.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-6844.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-3442.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2026/cve-2026-31790.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2025/cve-2025-69644.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2026-6846", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3441", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-25679", Product: "hummingbird-1:golang1.25-0:1.25.9-1.hum1", Status: fixtures.StatusAbsent},
			{ID: "CVE-2026-4647", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-6844", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3442", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-31790", Product: "hummingbird-1:openssl-fips-provider.src", Status: fixtures.StatusAffected},
			// {ID: "CVE-2025-69644", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
		},
	},
	// Current feed tests - hummingbird go image.
	// In the current feed hummingbird products appear under the "red_hat_hardened_images" namespace.
	// NOTE: CVE-2026-25679 (golang) is expected to FAIL because the current feed incorrectly
	// marks golang1.25/1.26 as known_affected when they are fixed in hummingbird per the beta feed.
	{
		Name:  "Hummingbird_CurrentFeed",
		Image: "quay.io/hummingbird/go@sha256:4bb8023430f26cfb4e779319a83d5d9577ce54fbf6433e9340e0035ab33b5ccc",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-6846.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-3441.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-25679.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-4647.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-6844.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-3442.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-31790.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2025/cve-2025-69644.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2026-6846", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3441", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-25679", Product: "red_hat_hardened_images:golang1.25", Status: fixtures.StatusAbsent},
			{ID: "CVE-2026-4647", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-6844", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3442", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-31790", Product: "red_hat_hardened_images:openssl-fips-provider.src", Status: fixtures.StatusAffected},
			// {ID: "CVE-2025-69644", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
		},
	},
}

func TestVEXFeeds(t *testing.T) {
	integration.Skip(t)
	integration.NeedDB(t)
	ctx := test.Logging(t)

	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)
	client := &http.Client{Timeout: 2 * time.Minute}

	auditor, err := NewClaircoreAuditor(ctx, t, &ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	for _, tc := range internalVEXTests {
		t.Run(tc.Name, func(t *testing.T) {
			docs, err := FetchVEXDocs(ctx, client, tc.VEXURLs)
			if err != nil {
				t.Fatalf("fetch VEX: %v", err)
			}
			fix := &Fixture{
				Reference:    tc.Image,
				VEXDocuments: docs,
				Expected:     tc.Expect,
			}
			Run(ctx, t, auditor, []string{tc.Image}, WithFixture(fix))
		})
	}
}
