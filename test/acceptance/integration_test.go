package acceptance

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	testpostgres "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/fixtures"
)

// FixturesRepo is the OCI repository containing acceptance test fixtures.
// Each image in this repo has VEX documents and expected results attached
// via OCI referrers.
const FixturesRepo = "quay.io/projectquay/clair-fixtures"

// ReadVEX reads a VEX file from testdata directory.
func readVEX(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read VEX file %q: %v", name, err)
	}
	return data
}

// TestAcceptanceRun tests the full acceptance framework using acceptance.Run.
func TestAcceptanceRun(t *testing.T) {
	integration.Skip(t)
	integration.NeedDB(t)
	ctx := test.Logging(t)

	// Get test databases
	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)

	// Create HTTP client
	client := &http.Client{Timeout: 2 * time.Minute}

	// Create auditor
	auditor, err := NewClaircoreAuditor(ctx, t, &ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
		Platform:    "linux/amd64",
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	// Test Go stdlib vulnerability
	t.Run("gobin", func(t *testing.T) {
		// Pinned digest for reproducibility. This image contains go1.20.14 stdlib.
		testFixture := &Fixture{
			Reference: "quay.io/projectquay/golang@sha256:561c49a22971d6ee75a88d3454639ca1b12b4e7ab396407a849d6ff2f1337ee7",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2026-123.json"),
			},
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2026-123",
					Product: "stdlib-1.20.14",
					Status:  fixtures.StatusAffected,
				},
			},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

	// Test Python pip vulnerability
	t.Run("python", func(t *testing.T) {
		// Use a UBI Python image pinned to a specific digest for reproducibility.
		// This image contains pip 24.2.
		testFixture := &Fixture{
			Reference: "registry.access.redhat.com/ubi9/python-311@sha256:c79635788fff0ca9b8a3dc6e9629bc54fe8f3606ca37c0a7d670d2149d7978a8",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2026-456-python.json"),
			},
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2026-456",
					Product: "pip-24.2",
					Status:  fixtures.StatusAffected,
				},
			},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

	// Test RHEL VEX with real Red Hat-published VEX file (CVE-2024-0727 for openssl).
	// This validates the specialised RHEL VEX parser that handles:
	// - Complex product tree relationships
	// - CPE-based repository matching
	// - Version comparison for fixed vs known_affected status
	t.Run("rhel-vex", func(t *testing.T) {
		// CVE-2024-0727 was fixed in openssl 3.0.7-27.el9 (RHEL 9.4.0.GA).
		// Use an older UBI9 image (tag 1-52) that has a vulnerable openssl version.
		// The VEX product IDs include the repository prefix (e.g., "BaseOS-9.4.0.GA:").
		testFixture := &Fixture{
			Reference: "registry.access.redhat.com/ubi9/python-311@sha256:2a52eb77f52a5be98ae19ac40ee784d1d8bf12bdfa37143a8f014b91f51e8f6f",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2024-0727-openssl.json"),
			},
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2024-0727",
					Product: "BaseOS-9.4.0.GA:openssl-1:3.0.7-27.el9.aarch64",
					Status:  fixtures.StatusAffected,
				},
				{
					ID:      "CVE-2024-0727",
					Product: "BaseOS-9.4.0.GA:openssl-libs-1:3.0.7-27.el9.aarch64",
					Status:  fixtures.StatusAffected,
				},
			},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

	t.Run("rhel-libssh", func(t *testing.T) {
		// The VEX document lists libssh, libssh-config, and libssh.src as known_affected.
		// Due to how matching works (source package matching), the vulnerabilities
		// that actually match are those with Package.Name="libssh" (the source package),
		// which have VEX product IDs "libssh" and "libssh.src".
		testFixture := &Fixture{
			Reference: "quay.io/app-sre/clair@sha256:3f1d3d79cc5f5c8728be5379f7e3e03a4c9bb1b5aca889ff27604a90e4ef9e22",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2026-0968.json"),
			},
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2026-0968",
					Product: "red_hat_enterprise_linux_8:libssh",
					Status:  fixtures.StatusAffected,
				},
				{
					ID:      "CVE-2026-0968",
					Product: "red_hat_enterprise_linux_8:libssh.src",
					Status:  fixtures.StatusAffected,
				},
			},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

	// Test RHEL and Go vulnerabilities.
	t.Run("rhel-gobin-fixed", func(t *testing.T) {
		testFixture := &Fixture{
			Reference: "quay.io/app-sre/clair@sha256:aab6f7f88d34e75e58cd808d3722d1cad7fdaa0c2148d4884f7d5d5ff6630d7b",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2026-123.json"),
				readVEX(t, "cve-2026-0968.json"),
				readVEX(t, "cve-2025-6176.json"),
			},
			Expected: []fixtures.ManifestRecord{
				{
					ID:      "CVE-2026-123",
					Product: "stdlib-1.20.14",
					Status:  fixtures.StatusAffected,
				},
				{
					ID:      "CVE-2026-0968",
					Product: "red_hat_enterprise_linux_8:libssh",
					Status:  fixtures.StatusAffected,
				},
				{
					ID:      "CVE-2026-0968",
					Product: "red_hat_enterprise_linux_8:libssh.src",
					Status:  fixtures.StatusAffected,
				},
				{
					ID:      "CVE-2025-6176",
					Product: "BaseOS-8.10.0.Z.MAIN.EUS:brotli-0:1.0.6-4.el8_10.aarch64",
					Status:  fixtures.StatusAffected,
				},
			},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

	// Test Perl module issue.
	t.Run("perl-module", func(t *testing.T) {
		testFixture := &Fixture{
			Reference: "registry.access.redhat.com/ubi8/perl-526@sha256:d9f5d5a9aed4173b4da07e18792f1393e1c4f7eafd767b690c49cdd0741fc757",
			Manifest:  "sha256:test",
			VEXDocuments: [][]byte{
				readVEX(t, "cve-2025-40907-perl.json"),
			},
			Expected: []fixtures.ManifestRecord{},
		}
		Run(ctx, t, auditor, []string{testFixture.Reference}, WithFixture(testFixture))
	})

}

// TestFixturesRepo runs acceptance tests against all images in the fixtures repository.
// Fixtures are discovered via the OCI referrers API - each image should have VEX
// documents and expected results attached.
func TestFixturesRepo(t *testing.T) {
	integration.Skip(t)
	integration.NeedDB(t)
	ctx := test.Logging(t)

	// List all tags in the fixtures repo
	rc := regclient.New(
		regclient.WithDockerCreds(),
		regclient.WithDockerCerts(),
	)
	defer rc.Close(ctx, ref.Ref{})

	repoRef, err := ref.New(FixturesRepo)
	if err != nil {
		t.Fatalf("parse fixtures repo: %v", err)
	}

	tags, err := rc.TagList(ctx, repoRef)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}

	// Filter out referrer fallback tags (sha256-<hex>) which seem to be from
	// regctl/regclient.
	// TODO(crozzy): Remove this once I find a way to not push these.
	referrerTag := regexp.MustCompile(`^sha256-[a-f0-9]{64}$`)
	var tagList []string
	for _, tag := range tags.Tags {
		if !referrerTag.MatchString(tag) {
			tagList = append(tagList, tag)
		}
	}
	if len(tagList) == 0 {
		t.Skip("no fixtures in repository")
	}

	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)
	client := &http.Client{Timeout: 2 * time.Minute}

	auditor, err := NewClaircoreAuditor(ctx, t, &ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
		Platform:    "linux/amd64",
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	for _, tag := range tagList {
		t.Run(tag, func(t *testing.T) {
			imageRef := FixturesRepo + ":" + tag
			// Pre-check if this image has the required referrer artifacts.
			// Skip images that aren't configured as test fixtures.
			fix, err := LoadFixture(ctx, imageRef)
			if errors.Is(err, ErrNotAFixture) {
				t.Skipf("skipping: %v", err)
			}
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			Run(ctx, t, auditor, []string{imageRef}, WithFixture(fix))
		})
	}
}
