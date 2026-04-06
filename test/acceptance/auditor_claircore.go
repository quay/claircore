package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/package-url/packageurl-go"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"

	"github.com/quay/claircore"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/nodejs"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	ctxlock "github.com/quay/claircore/pkg/ctxlock/v2"
	"github.com/quay/claircore/purl"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rhel/rhcc"
	rhelvex "github.com/quay/claircore/rhel/vex"
	"github.com/quay/claircore/ruby"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/fixtures"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/ubuntu"
)

// ClaircoreAuditor implements Auditor using claircore's libraries directly.
type ClaircoreAuditor struct {
	indexer      *libindex.Libindex
	matcher      *libvuln.Libvuln
	store        datastore.MatcherStore
	cachedArena  *test.CachedArena
	rc           *regclient.RegClient
	platform     platform.Platform
	purlRegistry *purl.Registry
}

// ClaircoreConfig holds configuration for creating a ClaircoreAuditor.
type ClaircoreConfig struct {
	IndexerDSN string
	MatcherDSN string
	Platform   string // Default: "linux/amd64"

	// IndexerPool and MatcherPool allow passing pre-existing pools (e.g., from test helpers).
	// If set, the corresponding DSN field is ignored.
	IndexerPool *pgxpool.Pool
	MatcherPool *pgxpool.Pool
}

// NewClaircoreAuditor creates a new auditor backed by claircore libraries.
// The testing.TB is used for layer caching - layers are cached in the global
// test cache directory and persist across test runs.
func NewClaircoreAuditor(ctx context.Context, t testing.TB, cfg *ClaircoreConfig, client *http.Client) (*ClaircoreAuditor, error) {
	if cfg.Platform == "" {
		cfg.Platform = "linux/amd64"
	}

	// Parse platform string (e.g., "linux/amd64")
	plat, err := platform.Parse(cfg.Platform)
	if err != nil {
		return nil, fmt.Errorf("parse platform %q: %w", cfg.Platform, err)
	}

	// Set up regclient with docker credentials
	rc := regclient.New(
		regclient.WithDockerCreds(),
		regclient.WithDockerCerts(),
	)

	// Create CachedArena for layer caching across test runs
	cachedArena := test.NewCachedArena(t)

	a := &ClaircoreAuditor{
		rc:           rc,
		platform:     plat,
		purlRegistry: newPurlRegistry(),
		cachedArena:  cachedArena,
	}

	// Set up indexer pool
	indexerPool := cfg.IndexerPool
	if indexerPool == nil {
		indexerPool, err = pgxpool.New(ctx, cfg.IndexerDSN)
		if err != nil {
			return nil, fmt.Errorf("indexer db connect: %w", err)
		}
	}
	indexerStore, err := postgres.InitPostgresIndexerStore(ctx, indexerPool, true)
	if err != nil {
		return nil, fmt.Errorf("indexer store init: %w", err)
	}
	indexerLocker, err := ctxlock.New(ctx, indexerPool)
	if err != nil {
		return nil, fmt.Errorf("indexer locker: %w", err)
	}

	a.indexer, err = libindex.New(ctx, &libindex.Options{
		Store:      indexerStore,
		Locker:     indexerLocker,
		FetchArena: cachedArena,
	}, client)
	if err != nil {
		return nil, fmt.Errorf("libindex.New: %w", err)
	}

	// Set up matcher pool
	matcherPool := cfg.MatcherPool
	if matcherPool == nil {
		matcherPool, err = pgxpool.New(ctx, cfg.MatcherDSN)
		if err != nil {
			return nil, fmt.Errorf("matcher db connect: %w", err)
		}
	}
	matcherStore, err := postgres.InitPostgresMatcherStore(ctx, matcherPool, true)
	if err != nil {
		return nil, fmt.Errorf("matcher store init: %w", err)
	}
	matcherLocker, err := ctxlock.New(ctx, matcherPool)
	if err != nil {
		return nil, fmt.Errorf("matcher locker: %w", err)
	}
	a.store = matcherStore

	a.matcher, err = libvuln.New(ctx, &libvuln.Options{
		Store:                    matcherStore,
		Locker:                   matcherLocker,
		Client:                   client,
		DisableBackgroundUpdates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("libvuln.New: %w", err)
	}

	return a, nil
}

// Close releases resources held by the auditor.
func (a *ClaircoreAuditor) Close(ctx context.Context) error {
	errs := make([]error, 3)
	if a.indexer != nil {
		errs[0] = a.indexer.Close(ctx)
	}
	if a.matcher != nil {
		errs[1] = a.matcher.Close(ctx)
	}
	if a.cachedArena != nil {
		errs[2] = a.cachedArena.Close(ctx)
	}
	return errors.Join(errs...)
}

// Audit implements Auditor.
func (a *ClaircoreAuditor) Audit(ctx context.Context, t testing.TB, reference string, csafDocs iter.Seq[io.Reader]) ([]Result, error) {
	slog.DebugContext(ctx, "starting audit", "ref", reference)

	// 1. Parse CSAF documents and load vulnerabilities into the matcher store
	vulns, err := a.parseCSAFDocuments(ctx, csafDocs)
	if err != nil {
		return nil, fmt.Errorf("parse CSAF: %w", err)
	}
	slog.DebugContext(ctx, "parsed CSAF documents", "vuln_count", len(vulns))
	for i, v := range vulns {
		slog.DebugContext(ctx, "parsed vulnerability", "idx", i, "name", v.Name, "pkg_name", v.Package.Name, "pkg_version", v.Package.Version)
	}
	if len(vulns) > 0 {
		_, err = a.store.UpdateVulnerabilities(ctx, "acceptance-test", "csaf", vulns)
		if err != nil {
			return nil, fmt.Errorf("load vulnerabilities: %w", err)
		}
	}

	// 2. Fetch manifest from OCI reference and create claircore.Manifest
	// This also pre-loads layers into the cache for the CachedArena.
	ccManifest, err := a.fetchOCIManifest(ctx, t, reference)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	// 3. Index the manifest
	ir, err := a.indexer.Index(ctx, ccManifest)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if ir.Err != "" {
		return nil, fmt.Errorf("index report error: %s", ir.Err)
	}
	slog.DebugContext(ctx, "indexed manifest", "packages", len(ir.Packages))

	// 4. Match vulnerabilities
	vr, err := a.matcher.Scan(ctx, ir)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	slog.DebugContext(ctx, "matched vulnerabilities", "packages_with_vulns", len(vr.PackageVulnerabilities), "total_vulns", len(vr.Vulnerabilities))

	// 5. Convert VulnerabilityReport to []Result
	return convertVulnReport(vr), nil
}

// NewPurlRegistry creates a purl.Registry populated with all ecosystem parsers.
func newPurlRegistry() *purl.Registry {
	r := purl.NewRegistry()

	// Register all ecosystem purl parsers
	r.RegisterPurlType(alpine.PURLType, alpine.PURLNamespace, alpine.ParsePURL)
	r.RegisterPurlType(aws.PURLType, aws.PURLNamespace, aws.ParsePURL)
	r.RegisterPurlType(debian.PURLType, debian.PURLNamespace, debian.ParsePURL)
	r.RegisterPurlType(gobin.PURLType, purl.NoneNamespace, gobin.ParsePURL)
	r.RegisterPurlType(java.PURLType, purl.NoneNamespace, java.ParsePURL)
	r.RegisterPurlType(nodejs.PURLType, purl.NoneNamespace, nodejs.ParsePURL)
	r.RegisterPurlType(oracle.PURLType, oracle.PURLNamespace, oracle.ParsePURL)
	r.RegisterPurlType(photon.PURLType, photon.PURLNamespace, photon.ParsePURL)
	r.RegisterPurlType(python.PURLType, purl.NoneNamespace, python.ParsePURL)
	r.RegisterPurlType(rhel.PURLType, rhel.PURLNamespace, rhel.ParseRPMPURL)
	r.RegisterPurlType(rhcc.PURLType, purl.NoneNamespace, rhcc.ParseOCIPURL)
	r.RegisterPurlType(ruby.PURLType, purl.NoneNamespace, ruby.ParsePURL)
	r.RegisterPurlType(suse.PURLType, suse.PURLNamespace, suse.ParsePURL)
	r.RegisterPurlType(ubuntu.PURLType, ubuntu.PURLNamespace, ubuntu.ParsePURL)

	return r
}

// ParseCSAFDocuments parses CSAF/VEX documents into claircore vulnerabilities.
// It detects RHEL VEX documents and uses the specialised RHEL VEX parser for those.
func (a *ClaircoreAuditor) parseCSAFDocuments(ctx context.Context, csafDocs iter.Seq[io.Reader]) ([]*claircore.Vulnerability, error) {
	// Buffer all readers since we may need to re-read documents (RHEL VEX detection
	// parses once to identify format, then re-parses with the specialized parser).
	var docs [][]byte
	for r := range csafDocs {
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("read CSAF doc: %w", err)
		}
		docs = append(docs, data)
	}
	slog.DebugContext(ctx, "buffered CSAF documents", "count", len(docs))

	var vulns []*claircore.Vulnerability

	// Create RHEL VEX parser once - it maintains caches for repository and product
	// lookups that are reused across documents.
	rhelParser := rhelvex.NewParser()

	for _, doc := range docs {
		c, err := csaf.Parse(bytes.NewReader(doc))
		if err != nil {
			return nil, fmt.Errorf("parse CSAF/VEX: %w", err)
		}

		trackingID := c.Document.Tracking.ID
		slog.DebugContext(ctx, "parsing CSAF/VEX document", "tracking_id", trackingID, "vuln_count", len(c.Vulnerabilities))

		// Detect RHEL VEX documents by publisher namespace and use the specialised parser.
		// RHEL VEX has complex product relationships and CPE-based repository matching.
		if c.Document.Publisher.Namespace == "https://www.redhat.com" {
			slog.DebugContext(ctx, "detected RHEL VEX document, using specialised parser", "tracking_id", trackingID)
			rhelVulns, err := rhelParser.Parse(ctx, doc)
			if err != nil {
				return nil, fmt.Errorf("parse RHEL VEX: %w", err)
			}
			vulns = append(vulns, rhelVulns...)
			continue
		}

		// Process each vulnerability in the document
		for _, v := range c.Vulnerabilities {
			vs, err := a.createVulnerabilitiesFromCSAFVuln(ctx, c, v)
			if err != nil {
				slog.WarnContext(ctx, "skipping vulnerability", "cve", v.CVE, "reason", err)
				continue
			}
			vulns = append(vulns, vs...)
		}
	}

	return vulns, nil
}

// ProductStatus indicates how a product is affected by a vulnerability.
// These map to CSAF product_status categories: known_affected, fixed, known_not_affected.
// See: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3239-vulnerabilities-property---product-status
type productStatus int

const (
	statusAffected    productStatus = iota // known_affected
	statusFixed                            // fixed
	statusNotAffected                      // known_not_affected
)

// CreateVulnerabilitiesFromCSAFVuln creates claircore vulnerabilities from a CSAF vulnerability entry.
// It processes known_affected, fixed, and known_not_affected products.
func (a *ClaircoreAuditor) createVulnerabilitiesFromCSAFVuln(ctx context.Context, c *csaf.CSAF, v csaf.Vulnerability) ([]*claircore.Vulnerability, error) {
	trackingID := c.Document.Tracking.ID

	// Collect links
	links := v.ReferenceURLs()
	if selfLink := c.SelfLink(); selfLink != "" {
		links = append(links, selfLink)
	}

	// Get description
	desc := v.Description()

	var vulns []*claircore.Vulnerability

	// Process known_affected products
	for _, productID := range v.ProductStatus["known_affected"] {
		vs, err := a.createVulnerabilitiesFromProduct(ctx, c, productID, trackingID, desc, links, statusAffected, v)
		if err != nil {
			slog.DebugContext(ctx, "skipping product", "product_id", productID, "reason", err)
			continue
		}
		vulns = append(vulns, vs...)
	}

	// Process fixed products - the pURL contains the fixed version
	for _, productID := range v.ProductStatus["fixed"] {
		vs, err := a.createVulnerabilitiesFromProduct(ctx, c, productID, trackingID, desc, links, statusFixed, v)
		if err != nil {
			slog.WarnContext(ctx, "skipping product", "product_id", productID, "reason", err)
			continue
		}
		vulns = append(vulns, vs...)
	}

	// TODO(crozzy): Process known_not_affected products here

	return vulns, nil
}

// CreateVulnerabilitiesFromProduct creates claircore vulnerabilities from a CSAF product.
func (a *ClaircoreAuditor) createVulnerabilitiesFromProduct(
	ctx context.Context,
	c *csaf.CSAF,
	productID, trackingID, desc string,
	links []string,
	status productStatus,
	v csaf.Vulnerability,
) ([]*claircore.Vulnerability, error) {
	// Walk relationships to find package and repo products
	pkgProductID, _, repoProductID, err := c.WalkRelationships(productID)
	if err != nil {
		return nil, err
	}

	// Get package product
	pkgProduct := c.ProductTree.FindProductByID(pkgProductID)
	if pkgProduct == nil {
		return nil, fmt.Errorf("package product %q not found", pkgProductID)
	}

	// Get pURL from package product
	purlStr, ok := pkgProduct.IdentificationHelper["purl"]
	if !ok {
		return nil, fmt.Errorf("no purl for product %q", pkgProductID)
	}

	pu, err := packageurl.FromString(purlStr)
	if err != nil {
		return nil, fmt.Errorf("parse purl %q: %w", purlStr, err)
	}

	// For "fixed" products, the pURL version IS the fixed version
	var fixedVersion string
	if status == statusFixed {
		fixedVersion = csaf.ExtractFixedVersion(pu)
	}

	// Extract severity from CSAF threat data
	severity, normSeverity := extractSeverity(c, productID)

	// Add remediation link if available
	if rem := c.FindRemediation(productID); rem != nil && rem.URL != "" {
		links = append(links, rem.URL)
	}

	// If repo product exists, try to get CPE and add to purl qualifiers
	if repoProductID != "" {
		repoProduct := c.ProductTree.FindProductByID(repoProductID)
		if repoProduct != nil {
			if cpeStr, ok := repoProduct.IdentificationHelper["cpe"]; ok {
				// Add repository_cpes qualifier for ecosystems that need it
				pu.Qualifiers = append(pu.Qualifiers, packageurl.Qualifier{
					Key:   "repository_cpes",
					Value: cpeStr,
				})
			}
		}
	}

	// Build links string with VEX product ID as URL fragment on the last link.
	linksStr := strings.Join(links, " ")
	if linksStr != "" {
		linksStr = linksStr + "#" + url.PathEscape(productID)
	}

	// Parse purl to get IndexRecords
	records, err := a.purlRegistry.Parse(ctx, pu)
	if err != nil {
		// If registry doesn't handle this purl type, create a basic vulnerability
		var unhandled purl.ErrUnhandledPurl
		if !errors.As(err, &unhandled) {
			return nil, fmt.Errorf("parse purl: %w", err)
		}
		// Fall back to basic vulnerability without proper IndexRecord
		return []*claircore.Vulnerability{{
			Name:               trackingID,
			Description:        desc,
			Issued:             v.ReleaseDate,
			Links:              linksStr,
			Severity:           severity,
			NormalizedSeverity: normSeverity,
			FixedInVersion:     fixedVersion,
			Package: &claircore.Package{
				Name:    pu.Name,
				Version: pu.Version,
				Kind:    types.BinaryPackage,
			},
		}}, nil
	}

	// Create a vulnerability for each IndexRecord
	var vulns []*claircore.Vulnerability
	for _, ir := range records {
		// Create a version range for matching.
		// TODO(crozzy): The need for a Range should ideally be signalled from the
		// VEX file itself, as not all ecosystems use version range matching. For now,
		// we create a range covering all versions when the package has a NormalizedVersion,
		// which works for ecosystems like gobin that opt into version filtering.
		var rng *claircore.Range
		if ir.Package != nil && ir.Package.NormalizedVersion.Kind != "" {
			rng = &claircore.Range{
				Lower: claircore.Version{Kind: ir.Package.NormalizedVersion.Kind},
				Upper: claircore.Version{
					Kind: ir.Package.NormalizedVersion.Kind,
					V:    [10]int32{65535}, // High upper bound
				},
			}
		}

		vuln := &claircore.Vulnerability{
			Name:               trackingID,
			Description:        desc,
			Issued:             v.ReleaseDate,
			Links:              linksStr,
			Severity:           severity,
			NormalizedSeverity: normSeverity,
			FixedInVersion:     fixedVersion,
			Package:            ir.Package,
			Repo:               ir.Repository,
			Dist:               ir.Distribution,
			Range:              rng,
			// TODO(crozzy): When statusNotAffected is enabled, set a field here
			// to indicate the product is known not affected
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// ExtractSeverity extracts severity information from CSAF threat and score data.
func extractSeverity(c *csaf.CSAF, productID string) (string, claircore.Severity) {
	// Try to get severity from threat data
	if t := c.FindThreat(productID, "impact"); t != nil {
		return t.Details, normalizeSeverity(t.Details)
	}

	// Fall back to CVSS score if available
	if sc := c.FindScore(productID); sc != nil {
		// Try to use the CVSS vector as severity string (prefer newer versions)
		if sc.CVSSV4 != nil && sc.CVSSV4.VectorString != "" {
			return sc.CVSSV4.VectorString, severityFromCVSSScore(sc.CVSSV4.BaseScore)
		}
		if sc.CVSSV3 != nil && sc.CVSSV3.VectorString != "" {
			return sc.CVSSV3.VectorString, severityFromCVSSScore(sc.CVSSV3.BaseScore)
		}
		if sc.CVSSV2 != nil && sc.CVSSV2.VectorString != "" {
			return sc.CVSSV2.VectorString, severityFromCVSSScore(sc.CVSSV2.BaseScore)
		}
	}

	return "Unknown", claircore.Unknown
}

// NormalizeSeverity converts a severity string to claircore.Severity.
func normalizeSeverity(s string) claircore.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return claircore.Critical
	case "high", "important":
		return claircore.High
	case "medium", "moderate":
		return claircore.Medium
	case "low":
		return claircore.Low
	case "negligible", "none":
		return claircore.Negligible
	default:
		return claircore.Unknown
	}
}

// SeverityFromCVSSScore converts a CVSS base score to claircore.Severity.
func severityFromCVSSScore(score float64) claircore.Severity {
	switch {
	case score >= 9.0:
		return claircore.Critical
	case score >= 7.0:
		return claircore.High
	case score >= 4.0:
		return claircore.Medium
	case score > 0.0:
		return claircore.Low
	default:
		return claircore.Negligible
	}
}

// FetchOCIManifest fetches an OCI manifest and converts to claircore.Manifest.
//
// Uses regclient to fetch the manifest and resolve platform-specific manifests
// from manifest lists. The returned claircore.Manifest has layer URIs that
// point to the OCI distribution blob endpoints.
//
// Layers are pre-loaded into the test cache via CachedArena.LoadLayerFromRegistry,
// so subsequent indexing will use cached layers rather than fetching from the registry.
func (a *ClaircoreAuditor) fetchOCIManifest(ctx context.Context, t testing.TB, reference string) (*claircore.Manifest, error) {
	// Parse the OCI reference
	r, err := ref.New(reference)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", reference, err)
	}

	// Fetch the manifest
	m, err := a.rc.ManifestGet(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	// If it's a manifest list/index, resolve to the platform-specific manifest
	if m.IsList() {
		desc, err := manifest.GetPlatformDesc(m, &a.platform)
		if err != nil {
			return nil, fmt.Errorf("resolve platform %s: %w", a.platform.String(), err)
		}
		// Fetch the platform-specific manifest
		r.Digest = desc.Digest.String()
		m, err = a.rc.ManifestGet(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("get platform manifest: %w", err)
		}
	}

	// Get the image manifest to extract layers
	mi, ok := m.(manifest.Imager)
	if !ok {
		return nil, fmt.Errorf("manifest is not an image manifest")
	}

	layers, err := mi.GetLayers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	// Build claircore.Manifest with layer info
	ccManifest := &claircore.Manifest{
		Hash:   claircore.MustParseDigest(m.GetDescriptor().Digest.String()),
		Layers: make([]*claircore.Layer, len(layers)),
	}

	for i, layer := range layers {
		digestStr := layer.Digest.String()

		// Pre-load layer into cache (will skip if already cached)
		layerRef := test.LayerRef{
			Registry: r.Registry,
			Name:     r.Repository,
			Digest:   digestStr,
		}
		a.cachedArena.LoadLayerFromRegistry(ctx, t, layerRef)

		// Construct blob URL using OCI distribution spec
		blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", r.Registry, r.Repository, digestStr)

		ccManifest.Layers[i] = &claircore.Layer{
			Hash:    claircore.MustParseDigest(digestStr),
			URI:     blobURL,
			Headers: make(map[string][]string),
		}
	}

	return ccManifest, nil
}

// ConvertVulnReport converts a VulnerabilityReport to Result slice.
// TODO(crozzy): This should be expanded once known_not_affected advisories
// are added to the results.
func convertVulnReport(vr *claircore.VulnerabilityReport) []Result {
	var results []Result

	for pkgID, vulnIDs := range vr.PackageVulnerabilities {
		pkg := vr.Packages[pkgID]
		for _, vulnID := range vulnIDs {
			vuln := vr.Vulnerabilities[vulnID]

			results = append(results, Result{
				TrackingID: vuln.Name,
				ProductID:  extractProductIDFromLinks(vuln.Links),
				Status:     fixtures.StatusAffected,
				Package:    fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
			})
		}
	}

	return results
}

// ExtractProductIDFromLinks extracts the VEX product ID from the URL fragment
// appended to the last link in the Links string.
func extractProductIDFromLinks(links string) string {
	if links == "" {
		return ""
	}
	parts := strings.Split(links, " ")
	lastLink := parts[len(parts)-1]
	u, err := url.Parse(lastLink)
	if err != nil {
		return ""
	}
	if u.Fragment == "" {
		return ""
	}
	productID, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return ""
	}
	return productID
}
