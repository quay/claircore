package vex

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/snappy"
	"github.com/package-url/packageurl-go"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/toolkit/types/cvss"
)

// Parse implements [driver.Updater].
func (u *Updater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	// NOOP
	return nil, errors.ErrUnsupported
}

// DeltaParse implements [driver.DeltaUpdater].
func (u *Updater) DeltaParse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, []string, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/vex/Updater.DeltaParse")
	// This map is needed for deduplication purposes, the compressed CSAF data will include
	// entries that have been subsequently updated in the changes.
	out := map[string][]*claircore.Vulnerability{}
	deleted := []string{}

	pc := newProductCache()
	rc := newRepoCache()

	r := bufio.NewReader(snappy.NewReader(contents))
	for b, err := r.ReadBytes('\n'); err == nil; b, err = r.ReadBytes('\n') {
		c, err := csaf.Parse(bytes.NewReader(b))
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing CSAF: %w", err)
		}
		name := c.Document.Tracking.ID
		if c.Document.Tracking.Status == "deleted" {
			deleted = append(deleted, name)
			continue
		}

		var selfLink string
		for _, r := range c.Document.References {
			if r.Category == "self" {
				selfLink = r.URL
			}
		}
		ctx = zlog.ContextWithValues(ctx, "link", selfLink)
		creator := newCreator(name, selfLink, c, pc, rc)
		for _, v := range c.Vulnerabilities {
			// Create vuln here, there should always be one vulnerability
			// here in the case of RH VEX but the spec allows multiple.
			links := []string{}
			for _, r := range v.References {
				links = append(links, r.URL)
			}
			// Useful for debugging
			links = append(links, selfLink)
			var desc string
			for _, n := range v.Notes {
				if n.Category == "description" {
					desc = n.Text
				}
			}

			protoVuln := func() *claircore.Vulnerability {
				v := &claircore.Vulnerability{
					Updater:            u.Name(),
					Name:               name,
					Description:        desc,
					Issued:             v.ReleaseDate,
					Links:              strings.Join(links, " "),
					Severity:           "Unknown",
					NormalizedSeverity: claircore.Unknown,
				}
				return v
			}
			// We're only bothered about known_affected and fixed,
			// not_affected and under_investigation are ignored.
			fixedVulns, err := creator.fixedVulnerabilities(ctx, v, protoVuln)
			if err != nil {
				return nil, nil, err
			}
			out[name] = fixedVulns
			knownAffectedVulns, err := creator.knownAffectedVulnerabilities(ctx, v, protoVuln)
			if err != nil {
				return nil, nil, err
			}
			out[name] = append(out[name], knownAffectedVulns...)
		}
	}
	vulns := []*claircore.Vulnerability{}
	for _, vs := range out {
		vulns = append(vulns, vs...)
	}

	return vulns, deleted, nil
}

// repoCache keeps a cache of all seen claircore.Repository objects.
type repoCache struct {
	cache map[string]*claircore.Repository
}

// NewRepoCache returns a repoCache with the backing map instantiated.
func newRepoCache() *repoCache {
	return &repoCache{
		cache: make(map[string]*claircore.Repository),
	}
}

// Get attempts to find a repo in the cache identified by a WFN. If
// it isn't found a repo is created and returned.
func (rc *repoCache) Get(cpe cpe.WFN) *claircore.Repository {
	if r, ok := rc.cache[cpe.String()]; ok {
		return r
	}
	r := &claircore.Repository{
		CPE:  cpe,
		Name: cpe.String(),
		Key:  repoKey,
	}
	rc.cache[cpe.String()] = r
	return r
}

// productCache keeps a cache of all seen csaf.Products.
type productCache struct {
	cache map[string]*csaf.Product
}

// NewProductCache returns a productCache with the backing
// map instantiated.
func newProductCache() *productCache {
	return &productCache{
		cache: make(map[string]*csaf.Product),
	}
}

// Get is a wrapper around the FindProductByID method that
// attempts to return from the cache before traversing the
// CSAF object.
func (pc *productCache) Get(productID string, c *csaf.CSAF) *csaf.Product {
	if p, ok := pc.cache[productID]; ok {
		return p
	}
	p := c.ProductTree.FindProductByID(productID)
	pc.cache[productID] = p
	return p
}

// NewCreator returns a creator object used for processing parts of a VEX file
// and returning claircore.Vulnerabilities.
func newCreator(vulnName, vulnLink string, c *csaf.CSAF, pc *productCache, rc *repoCache) *creator {
	return &creator{
		vulnName:       vulnName,
		vulnLink:       vulnLink,
		uniqueVulnsIdx: make(map[string]int),
		c:              c,
		pc:             pc,
		rc:             rc,
	}
}

// creator attempts to lessen the memory burden when creating vulnerability objects
// by caching objects that are used multiple times during prcessing.
type creator struct {
	vulnName, vulnLink string
	uniqueVulnsIdx     map[string]int
	fixedVulns         []claircore.Vulnerability
	c                  *csaf.CSAF
	pc                 *productCache
	rc                 *repoCache
}

// WalkRelationships attempts to resolve a relationship until we have a package product_id and
// a repo product_id. Relationships can be nested. If the pkgID and the repoID are the same we
// either found no relationship or a relationship where both ends are pointing to the same
// product_id, either way we don't have enough data to create a vulnerability.
func walkRelationships(productID string, doc *csaf.CSAF) (string, string, error) {
	pkgID, repoID := extractProductNames(productID, productID, doc)
	if pkgID == repoID {
		return "", "", fmt.Errorf("could not extract a distict pkgID and repoID from %q", productID)
	}
	return pkgID, repoID, nil
}

// ExtractProductNames recursively looks up the package product_id and the repo product_id.
// The assumtion is that the repo is always the last found relates_to_product_reference and the
// package is the last found product_reference.
func extractProductNames(prodRelID string, repoRelID string, c *csaf.CSAF) (string, string) {
	prodRel := c.FindRelationship(prodRelID, "default_component_of")
	if prodRel != nil {
		prodRelID, _ = extractProductNames(prodRel.ProductRef, prodRel.RelatesToProductRef, c)
	}
	repoRel := c.FindRelationship(repoRelID, "default_component_of")
	if repoRel != nil {
		_, repoRelID = extractProductNames(repoRel.ProductRef, repoRel.RelatesToProductRef, c)
	}
	return prodRelID, repoRelID
}

// KnownAffectedVulnerabilities processes the "known_affected" array of products
// in the VEX object.
func (c *creator) knownAffectedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	unrelatedProductIDs := []string{}
	debugEnabled := zlog.Debug(ctx).Enabled()
	out := []*claircore.Vulnerability{}
	for _, pc := range v.ProductStatus["known_affected"] {
		pkgName, repoName, err := walkRelationships(pc, c.c)
		if err != nil && debugEnabled {
			unrelatedProductIDs = append(unrelatedProductIDs, pc)
			// It's possible to get here due to middleware not having a defined component:package
			// relationship.
		}
		if strings.HasPrefix(pkgName, "kernel") {
			// We don't want to ingest kernel advisories as
			// containers have no say in the kernel.
			continue
		}

		repoProd := c.pc.Get(repoName, c.c)
		if repoProd == nil {
			zlog.Warn(ctx).
				Str("prod", repoName).
				Msg("could not find product in product tree")
			continue
		}
		cpeHelper, ok := repoProd.IdentificationHelper["cpe"]
		if !ok {
			zlog.Warn(ctx).
				Str("prod", repoName).
				Msg("could not find cpe helper type in product")
			continue
		}

		// pkgName will be overridden if we find a valid pURL
		compProd := c.pc.Get(pkgName, c.c)
		if compProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("pkg", pkgName).
				Msg("could not find package in product tree")
			continue
		}
		// It is possible that we will not find a pURL, in that case
		// the package.Name will be reported as-is.
		purlHelper, ok := compProd.IdentificationHelper["purl"]
		if ok {
			purl, err := packageurl.FromString(purlHelper)
			switch {
			case err != nil:
				zlog.Warn(ctx).
					Str("purl", purlHelper).
					Err(err).
					Msg("could not parse PURL")
			default:
				pkgName = purl.Name
			}
			if purl.Type != packageurl.TypeRPM || purl.Namespace != "redhat" {
				// Just ingest advisories that are Red Hat RPMs, this will
				// probably change down the line when we consolidate updaters.
				continue
			}
		}

		vuln := protoVulnFunc()
		// What is the deal here? Just stick the package name in and f-it?
		// That's the plan so far as there's no PURL product ID helper.
		vuln.Package = &claircore.Package{
			Name: pkgName,
			Kind: claircore.SOURCE,
		}
		ch := escapeCPE(cpeHelper)
		wfn, err := cpe.Unbind(ch)
		if err != nil {
			return nil, fmt.Errorf("could not unbind cpe: %s %w", ch, err)
		}
		vuln.Repo = c.rc.Get(wfn)
		sc := c.c.FindScore(pc)
		if sc != nil {
			vuln.Severity, err = cvssVectorFromScore(sc)
			if err != nil {
				return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.vulnLink)
			}
		}
		if t := c.c.FindThreat(pc, "impact"); t != nil {
			vuln.NormalizedSeverity = common.NormalizeSeverity(t.Details)
		} else {
			if sc != nil && cvssBaseScoreFromScore(sc) == 0.0 {
				// This has no threat object and a 0.0 baseScore, disregard.
				continue
			}
		}
		out = append(out, vuln)
	}
	if len(unrelatedProductIDs) > 0 {
		zlog.Debug(ctx).
			Strs("product_ids", unrelatedProductIDs).
			Msg("skipped unrelatable product_ids")
	}

	return out, nil
}

func (c *creator) lookupVulnerability(vulnKey string, protoVulnFunc func() *claircore.Vulnerability) (*claircore.Vulnerability, bool) {
	idx, ok := c.uniqueVulnsIdx[vulnKey]
	if !ok {
		idx = len(c.fixedVulns)
		if cap(c.fixedVulns) > idx {
			c.fixedVulns = c.fixedVulns[:idx+1]
		} else {
			c.fixedVulns = append(c.fixedVulns, claircore.Vulnerability{})
		}
		c.fixedVulns[idx] = *protoVulnFunc()
		c.uniqueVulnsIdx[vulnKey] = idx
	}
	return &c.fixedVulns[idx], ok
}

// FixedVulnerabilities processes the "fixed" array of products in the
// VEX object.
func (c *creator) fixedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	unrelatedProductIDs := []string{}
	debugEnabled := zlog.Debug(ctx).Enabled()
	for _, pc := range v.ProductStatus["fixed"] {
		pkgName, repoName, err := walkRelationships(pc, c.c)
		if err != nil && debugEnabled {
			unrelatedProductIDs = append(unrelatedProductIDs, pc)
			// It's possible to get here due to middleware not having a defined component:package
			// relationship.
			continue
		}

		repoProd := c.pc.Get(repoName, c.c)
		if repoProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("prod", repoName).
				Msg("could not find product in product tree")
			continue
		}
		cpeHelper, ok := repoProd.IdentificationHelper["cpe"]
		if !ok {
			zlog.Warn(ctx).
				Str("prod", repoName).
				Msg("could not find cpe helper type in product")
			continue
		}
		compProd := c.pc.Get(pkgName, c.c)
		if compProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("pkg", pkgName).
				Msg("could not find package in product tree")
			continue
		}
		purlHelper, ok := compProd.IdentificationHelper["purl"]
		if !ok {
			zlog.Warn(ctx).
				Str("pkg", pkgName).
				Msg("could not find purl helper type in product")
			continue
		}
		purl, err := packageurl.FromString(purlHelper)
		if err != nil {
			zlog.Warn(ctx).
				Str("purl", purlHelper).
				Msg("could not parse PURL")
			continue
		}
		if strings.HasPrefix(purl.Name, "kernel") {
			// We don't want to ingest kernel advisories as
			// containers have no say in the kernel.
			continue
		}
		if purl.Type != packageurl.TypeRPM || purl.Namespace != "redhat" {
			// Just ingest advisories that are Red Hat RPMs, this will
			// probably change down the line when we consolidate updaters.
			continue
		}

		fixedIn := epochVersion(&purl)
		vulnKey := createPackageKey(repoName, purl.Name, fixedIn)
		arch := purl.Qualifiers.Map()["arch"]
		if vuln, ok := c.lookupVulnerability(vulnKey, protoVulnFunc); ok && arch != "" {
			// We've already found this package, just append the arch
			vuln.Package.Arch = vuln.Package.Arch + "|" + arch
		} else {
			vuln.FixedInVersion = fixedIn
			vuln.Package = &claircore.Package{
				Name: purl.Name,
				Kind: claircore.BINARY,
			}

			if arch != "" {
				vuln.Package.Arch = arch
				vuln.ArchOperation = claircore.OpPatternMatch
			}

			ch := escapeCPE(cpeHelper)
			wfn, err := cpe.Unbind(ch)
			if err != nil {
				return nil, fmt.Errorf("could not unbind cpe: %s %w", ch, err)
			}
			vuln.Repo = c.rc.Get(wfn)
			// Find remediations and add RHSA URL to links
			rem := c.c.FindRemediation(pc)
			if rem != nil {
				vuln.Links = vuln.Links + " " + rem.URL
			}
			sc := c.c.FindScore(pc)
			if sc != nil {
				vuln.Severity, err = cvssVectorFromScore(sc)
				if err != nil {
					return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.vulnLink)
				}
			}
			if t := c.c.FindThreat(pc, "impact"); t != nil {
				vuln.NormalizedSeverity = common.NormalizeSeverity(t.Details)
			} else {
				if sc != nil && cvssBaseScoreFromScore(sc) == 0.0 {
					// This has no threat object and a 0.0 baseScore, disregard.
					continue
				}
			}
		}
	}
	if len(unrelatedProductIDs) > 0 {
		zlog.Debug(ctx).
			Strs("product_ids", unrelatedProductIDs).
			Msg("skipped unrelatable product_ids")
	}

	out := make([]*claircore.Vulnerability, len(c.fixedVulns))
	for i := range c.fixedVulns {
		out[i] = &c.fixedVulns[i]
	}
	return out, nil
}

func cvssBaseScoreFromScore(sc *csaf.Score) float64 {
	switch {
	case sc.CVSSV4 != nil:
		return sc.CVSSV4.BaseScore
	case sc.CVSSV3 != nil:
		return sc.CVSSV3.BaseScore
	case sc.CVSSV2 != nil:
		return sc.CVSSV2.BaseScore
	default:
		return 0.0
	}
}

func cvssVectorFromScore(sc *csaf.Score) (vec string, err error) {
	switch {
	case sc.CVSSV4 != nil:
		_, err = cvss.ParseV4(sc.CVSSV4.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		vec = sc.CVSSV4.VectorString
		return
	case sc.CVSSV3 != nil:
		_, err = cvss.ParseV3(sc.CVSSV3.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv3 vector string %w", err)
			return
		}
		vec = sc.CVSSV3.VectorString
		return
	case sc.CVSSV2 != nil:
		_, err = cvss.ParseV2(sc.CVSSV2.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		vec = sc.CVSSV2.VectorString
		return
	default:
		err = errors.New("could not find a valid CVSS object")
	}
	return
}

// CreatePackageKey creates a unique key to describe an arch agnostic
// package for deduplication purposes.
// i.e. AppStream-8.2.0.Z.TUS:python3-idle-0:3.6.8-24.el8_2.2
func createPackageKey(repo, name, fixedIn string) string {
	// The other option here is just to use repo + PURL string
	// w/o the qualifiers I suppose instead of repo + NEVR.
	return repo + ":" + name + "-" + fixedIn
}

func epochVersion(purl *packageurl.PackageURL) string {
	epoch := "0"
	if e, ok := purl.Qualifiers.Map()["epoch"]; ok {
		epoch = e
	}
	return epoch + ":" + purl.Version
}

func escapeCPE(ch string) string {
	c := strings.Split(ch, ":")
	for i := 0; i < len(c); i++ {
		if strings.HasSuffix(c[i], "*") {
			c[i] = c[i][:len(c[i])-1] + `%02`
		}
		c[i] = strings.ReplaceAll(c[i], "?", "%01")
	}
	return strings.Join(c, ":")
}
