package periodic

import (
	"net/http"
	"testing"
	"time"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/acceptance"
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

// vexFeedTests compares the current and beta Red Hat VEX feeds against known images.
//
// CVEs tested:
//   - CVE-2023-4911: glibc (Looney Tunables)
//   - CVE-2023-2650: openssl
//   - CVE-2023-38545: curl (beta feed only - current feed CPEs don't match UBI9)
//   - CVE-2026-6846, CVE-2026-3441, CVE-2026-4647, CVE-2026-6844, CVE-2026-3442,
//     CVE-2026-25679, CVE-2026-31790, CVE-2025-69644
var vexFeedTests = []vexFeedTest{
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
			{ID: "CVE-2023-4911", Product: "rhel-br-9.2.0.z::baseos:glibc-common-0:2.34-60.el9_2.7", Status: fixtures.StatusAffected},
			{ID: "CVE-2023-2650", Product: "rhel-br-9.2.0.z::baseos:openssl-libs-1:3.0.7-16.el9_2", Status: fixtures.StatusAffected},
			// CVE-2023-38545 (curl): ubi9:9.0.0 ships curl-minimal 7.76.1-14.el9_0.5, which is
			// below the beta-feed fixed version, so the package is affected.
			{ID: "CVE-2023-38545", Product: "rhel-br-9.2.0.z::baseos:curl-minimal-0:7.76.1-23.el9_2.4", Status: fixtures.StatusAffected},
		},
	},
	// Beta feed tests - patched (non-vulnerable) image (ubi9:9.3)
	{
		Name:  "UBI9_93_Patched_BetaFeed",
		Image: "registry.access.redhat.com/ubi9:9.3",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-2650.json",
			"https://security.access.redhat.com/data/csaf/v2/vex-feed/2023/cve-2023-38545.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "rhel-br-9.2.0.z::baseos:glibc-common-0:2.34-60.el9_2.7", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-2650", Product: "rhel-br-9.2.0.z::baseos:openssl-libs-1:3.0.7-16.el9_2", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-38545", Product: "rhel-br-9.2.0.z::baseos:curl-minimal-0:7.76.1-23.el9_2.4", Status: fixtures.StatusAbsent},
		},
	},
	// Current feed tests - hummingbird go image.
	// Hummingbird products appear under the "Red Hat Hardened Images" namespace in the current feed.
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
			{ID: "CVE-2026-6846", Product: "Red Hat Hardened Images:binutils-main@x86_64", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3441", Product: "Red Hat Hardened Images:binutils-main@x86_64", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-4647", Product: "Red Hat Hardened Images:binutils-main@x86_64", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-6844", Product: "red_hat_hardened_images:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3442", Product: "Red Hat Hardened Images:binutils-main@x86_64", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-31790", Product: "Red Hat Hardened Images:openssl-fips-provider-main@x86_64", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-25679", Product: "Red Hat Hardened Images:golang1-25-main@x86_64", Status: fixtures.StatusAbsent},
			{ID: "CVE-2025-69644", Product: "Red Hat Hardened Images:binutils-main@x86_64", Status: fixtures.StatusAbsent},
		},
	},
	// Beta feed tests - hummingbird go image.
	// CVE-2026-6844 remains known_affected on binutils.src. Other binutils CVEs are "fixed" at
	// 2.45.1-5.1.hum1; the image ships 2.45.1-5.hum1 and should be reported Affected.
	// CVE-2025-69644 is fixed at the installed binutils NVR and correctly absent.
	// CVE-2026-25679 is fixed at the installed golang version and correctly absent.
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
			{ID: "CVE-2026-6846", Product: "hummingbird-1:binutils-0:2.45.1-5.1.hum1", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3441", Product: "hummingbird-1:binutils-0:2.45.1-5.1.hum1", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-4647", Product: "hummingbird-1:binutils-0:2.45.1-5.1.hum1", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-6844", Product: "hummingbird-1:binutils.src", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-3442", Product: "hummingbird-1:binutils-0:2.45.1-5.1.hum1", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-31790", Product: "hummingbird-1:openssl-fips-provider-so-0:3.0.7-1.2.hum1", Status: fixtures.StatusAffected},
			{ID: "CVE-2026-25679", Product: "hummingbird-1:golang1.25-0:1.25.9-1.hum1", Status: fixtures.StatusAbsent},
			{ID: "CVE-2025-69644", Product: "hummingbird-1:binutils-0:2.45.1-5.hum1", Status: fixtures.StatusAbsent},
		},
	},
}

// TestVEXFeeds exercises current and beta Red Hat VEX feeds against known images.
// Run with: go test ./test/periodic -enable -run TestVEXFeeds -timeout 30m
func TestVEXFeeds(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)
	client := &http.Client{Timeout: 2 * time.Minute}

	auditor, err := acceptance.NewClaircoreAuditor(ctx, t, &acceptance.ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	for _, tc := range vexFeedTests {
		t.Run(tc.Name, func(t *testing.T) {
			docs, err := acceptance.FetchVEXDocs(ctx, client, tc.VEXURLs)
			if err != nil {
				t.Fatalf("fetch VEX: %v", err)
			}
			fix := &acceptance.Fixture{
				Reference:    tc.Image,
				VEXDocuments: docs,
				Expected:     tc.Expect,
			}
			acceptance.Run(ctx, t, auditor, []string{tc.Image}, acceptance.WithFixture(fix))
		})
	}
}
