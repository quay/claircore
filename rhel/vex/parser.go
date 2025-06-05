package vex

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/klauspost/compress/snappy"
	"github.com/package-url/packageurl-go"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/rhel/rhcc"
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
	for n, vs := range out {
		if len(vs) == 0 {
			// If there are no vulns for this CVE make sure we signal that
			// it is deleted in case it once had vulns.
			deleted = append(deleted, n)
			continue
		}
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

// WalkRelationships attempts to resolve a relationship until we have a package product_id,
// a repo product_id and possibly a package module product_id. Relationships can be nested.
// If we don't get an initial relationship or we don't get two component parts we cannot
// create a vulnerability. We never see more than 3 components in the wild but if we did
// we'd assume the component next to the repo product_id is the package module product_id.
func walkRelationships(productID string, doc *csaf.CSAF) (string, string, string, error) {
	prodRel := doc.FindRelationship(productID, "default_component_of")
	if prodRel == nil {
		return "", "", "", fmt.Errorf("cannot determine initial relationship for %q", productID)
	}
	comps := extractProductNames(prodRel.ProductRef, prodRel.RelatesToProductRef, []string{}, doc)
	switch {
	case len(comps) == 2:
		// We have a package and repo
		return comps[0], "", comps[1], nil
	case len(comps) > 2:
		// We have a package, module and repo
		return comps[0], comps[len(comps)-2], comps[len(comps)-1], nil
	default:
		return "", "", "", fmt.Errorf("cannot determine relationships for %q", productID)
	}
}

// ExtractProductNames recursively looks up product_id relationships and adds them to a
// component slice in order. prodRef (and it's potential children) are leftmost in the return
// slice and relatesToProdRef (and it's potential children) are rightmost.
// For example: prodRef=a_pkg and relatesToProdRef=a_repo:a_module and a Relationship where
// Relationship.ProductRef=a_module and Relationship.RelatesToProductRef=a_repo the return
// slice would be: ["a_pkg", "a_module", "a_repo"].
func extractProductNames(prodRef, relatesToProdRef string, comps []string, c *csaf.CSAF) []string {
	prodRel := c.FindRelationship(prodRef, "default_component_of")
	if prodRel != nil {
		comps = extractProductNames(prodRel.ProductRef, prodRel.RelatesToProductRef, comps, c)
	} else {
		comps = append(comps, prodRef)
	}
	repoRel := c.FindRelationship(relatesToProdRef, "default_component_of")
	if repoRel != nil {
		comps = extractProductNames(repoRel.ProductRef, repoRel.RelatesToProductRef, comps, c)
	} else {
		comps = append(comps, relatesToProdRef)
	}
	return comps
}

// KnownAffectedVulnerabilities processes the "known_affected" array of products
// in the VEX object.
func (c *creator) knownAffectedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	ranger := newRanger()
	unrelatedProductIDs := []string{}
	debugEnabled := zlog.Debug(ctx).Enabled()
	out := []*claircore.Vulnerability{}
	for _, pc := range v.ProductStatus["known_affected"] {
		pkgName, modName, repoName, err := walkRelationships(pc, c.c)
		if err != nil {
			// It's possible to get here due to middleware not having a defined component:package
			// relationship.
			if debugEnabled {
				unrelatedProductIDs = append(unrelatedProductIDs, pc)
			}
			continue
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

		// Deal with modules if we found one.
		if modName != "" {
			modProd := c.pc.Get(modName, c.c)
			modName, err = createPackageModule(modProd)
			if err != nil {
				zlog.Warn(ctx).
					Str("module", modName).
					Err(err).
					Msg("could not create package module")
			}
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
		vuln := protoVulnFunc()

		ch := escapeCPE(cpeHelper)
		wfn, err := cpe.Unbind(ch)
		if err != nil {
			return nil, fmt.Errorf("could not unbind cpe: %s %w", ch, err)
		}
		vuln.Repo = c.rc.Get(wfn)
		// It is possible that we will not find a pURL, in that case
		// the package.Name will be reported as-is.
		purlHelper, ok := compProd.IdentificationHelper["purl"]
		if ok {
			purl, err := packageurl.FromString(purlHelper)
			if err != nil {
				zlog.Warn(ctx).
					Str("purlHelper", purlHelper).
					Err(err).
					Msg("could not parse PURL")
				continue
			}
			if !checkPURL(purl) {
				continue
			}
			if pn, err := extractPackageName(purl); err != nil {
				zlog.Warn(ctx).
					Str("purl", purl.String()).
					Err(err).
					Msg("could not extract package name from pURL")
			} else {
				pkgName = pn
			}

			if mn, ok := purl.Qualifiers.Map()["rpmmod"]; ok {
				// It is possible to have a module name in the purl, not in the relationship.
				modName = mn
			}

			if purl.Type == packageurl.TypeOCI {
				// Override repo if we're dealing with a container image
				vuln.Repo = &rhcc.GoldRepo
				vuln.Range, err = ranger.add(pkgName, vuln.FixedInVersion)
				if err != nil {
					zlog.Warn(ctx).
						Str("FixedInVersion", vuln.FixedInVersion).
						Err(err).
						Msg("could not parse version into range")
					continue
				}
			}
		}

		// What is the deal here? Just stick the package name in and f-it?
		// That's the plan so far as there's no PURL product ID helper.
		vuln.Package = &claircore.Package{
			Name:   pkgName,
			Kind:   claircore.SOURCE,
			Module: modName,
		}
		sc := c.c.FindScore(pc)
		if sc != nil {
			var err error
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
	ranger.resetLowest()
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

type ranger struct {
	lowest map[string]*claircore.Range
}

func newRanger() *ranger {
	return &ranger{
		lowest: map[string]*claircore.Range{},
	}
}

// Add takes a packageName and a fixedInVersion and returns a *claircore.Range relating
// to the fixedInVersion. Add also saves the lowest range per packageName that it's seen.
// This allows resetLowest() to zero out the lowest values we saw per packageName.
func (r *ranger) add(packageName, fixedInVersion string) (*claircore.Range, error) {
	var rng = &claircore.Range{}

	if fixedInVersion == "" {
		zeroVer := &rhctag.Version{}
		rng.Lower = zeroVer.Version(true)
		highestVer := rhctag.Version{
			Major: math.MaxInt32, // Everything is vulnerable
		}
		rng.Upper = highestVer.Version(true)
	} else {
		firstPatch, err := rhctag.Parse(fixedInVersion)
		if err != nil {
			return nil, err
		}
		rng.Upper = firstPatch.Version(false)
		rng.Lower = firstPatch.Version(true)
	}
	curLow := r.lowest[packageName]
	if curLow == nil || rng.Lower.Compare(&curLow.Lower) == -1 {
		// If the vulns version is less than our current lower for that package, switch it.
		r.lowest[packageName] = rng
	}

	return rng, nil
}

// ResetLowest Zeros out all the lowest versions' lower bounds
func (r *ranger) resetLowest() {
	zeroVer := &rhctag.Version{}
	for _, r := range r.lowest {
		r.Lower = zeroVer.Version(true)
	}
}

// FixedVulnerabilities processes the "fixed" array of products in the
// VEX object.
func (c *creator) fixedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	ranger := newRanger()
	unrelatedProductIDs := []string{}
	debugEnabled := zlog.Debug(ctx).Enabled()
	for _, pc := range v.ProductStatus["fixed"] {
		pkgName, modName, repoName, err := walkRelationships(pc, c.c)
		if err != nil {
			// It's possible to get here due to middleware not having a defined component:package
			// relationship.
			if debugEnabled {
				unrelatedProductIDs = append(unrelatedProductIDs, pc)
			}
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

		// Deal with modules if we found one.
		if modName != "" {
			modProd := c.pc.Get(modName, c.c)
			modName, err = createPackageModule(modProd)
			if err != nil {
				zlog.Warn(ctx).
					Str("module", modName).
					Err(err).
					Msg("could not create package module")
			}
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
		if !checkPURL(purl) {
			continue
		}
		fixedIn, err := extractFixedInVersion(purl)
		if err != nil {
			zlog.Warn(ctx).
				Str("purl", purl.String()).
				Err(err).
				Msg("error extracting fixed_in version from pURL")
			continue
		}
		packageName, err := extractPackageName(purl)
		if err != nil {
			zlog.Warn(ctx).
				Str("purl", purl.String()).
				Err(err).
				Msg("error extracting package name from pURL")
			continue
		}
		if mn, ok := purl.Qualifiers.Map()["rpmmod"]; ok {
			// It is possible to have a module name in the purl, not in the relationship.
			modName = mn
		}

		vulnKey := createPackageKey(repoName, modName, purl.Name, fixedIn)
		arch := extractArch(purl)
		if vuln, ok := c.lookupVulnerability(vulnKey, protoVulnFunc); ok && arch != "" {
			// We've already found this package, just append the arch
			vuln.Package.Arch = vuln.Package.Arch + "|" + arch
		} else {
			vuln.FixedInVersion = fixedIn
			vuln.Package = &claircore.Package{
				Name:   packageName,
				Kind:   claircore.BINARY,
				Module: modName,
			}

			if arch != "" {
				vuln.Package.Arch = arch
				vuln.ArchOperation = claircore.OpPatternMatch
			}
			switch purl.Type {
			case packageurl.TypeRPM:
				ch := escapeCPE(cpeHelper)
				wfn, err := cpe.Unbind(ch)
				if err != nil {
					return nil, fmt.Errorf("could not unbind cpe: %s %w", cpeHelper, err)
				}
				vuln.Repo = c.rc.Get(wfn)
			case packageurl.TypeOCI:
				vuln.Repo = &rhcc.GoldRepo
				vuln.Range, err = ranger.add(packageName, vuln.FixedInVersion)
				if err != nil {
					zlog.Warn(ctx).
						Str("FixedInVersion", vuln.FixedInVersion).
						Err(err).
						Msg("could not parse version into range")
					continue
				}
			default:
				continue
			}

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
	ranger.resetLowest()
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
// i.e. AppStream-8.2.0.Z.TUS:a_module:python3-idle-0:3.6.8-24.el8_2.2
func createPackageKey(repo, mod, name, fixedIn string) string {
	// The other option here is just to use repo + PURL string
	// w/o the qualifiers I suppose instead of repo + NEVR.
	return repo + ":" + mod + ":" + name + "-" + fixedIn
}

func createPackageModule(p *csaf.Product) (string, error) {
	modPURLHelper, ok := p.IdentificationHelper["purl"]
	if !ok {
		return "", nil
	}
	purl, err := packageurl.FromString(modPURLHelper)
	if err != nil {
		return "", err
	}
	if purl.Type != "rpmmod" {
		return "", fmt.Errorf("invalid RPM module PURL: %q", purl.String())
	}
	var modName string
	switch {
	case purl.Namespace == "redhat":
		version, _, _ := strings.Cut(purl.Version, ":")
		modName = purl.Name + ":" + version
	case strings.HasPrefix(purl.Namespace, "redhat/"):
		// Account for the case where the PURL is unconventional
		// e.g. pkg:rpmmod/redhat/postgresql:15/postgresql
		_, modName, _ = strings.Cut(purl.Namespace, "/")
	default:
		// We never see this in the wild but account for it just in case.
		return "", fmt.Errorf("non-Red Hat PURL")
	}
	return modName, nil
}

// ExtractFixedInVersion deals with 2 pURL types, TypeRPM and TypeOCI
//   - TypeOCI: return the tag qualifier.
//   - TypeRPM: check for an epoch qualifier and prepend it to the purl.Version.
//     If no epoch qualifier, default to 0.
func extractFixedInVersion(purl packageurl.PackageURL) (string, error) {
	switch purl.Type {
	case packageurl.TypeOCI:
		t, ok := purl.Qualifiers.Map()["tag"]
		if !ok {
			return "", fmt.Errorf("could not find tag qualifier for OCI purl type %s", purl.String())
		}
		return t, nil
	case packageurl.TypeRPM:
		epoch := "0"
		if e, ok := purl.Qualifiers.Map()["epoch"]; ok {
			epoch = e
		}
		return epoch + ":" + purl.Version, nil
	default:
		return "", fmt.Errorf("unexpected purl type %s", purl.Type)
	}
}

// ExtractPackageName deals with 2 pURL types, TypeRPM and TypeOCI
//   - TypeOCI: check if there is Namespace and Name i.e. rhel7/rhel-atomic
//     and return that, if not, check for a repository_url qualifier. If the
//     repository_url exists then use the namespace/name part, if not, use
//     the purl.Name.
//   - TypeRPM: Just return the purl.Name.
func extractPackageName(purl packageurl.PackageURL) (string, error) {
	switch purl.Type {
	case packageurl.TypeOCI:
		if purl.Namespace != "" {
			return purl.Namespace + "/" + purl.Name, nil
		}
		// Try finding an image name from the tag qualifier
		ru, ok := purl.Qualifiers.Map()["repository_url"]
		if !ok {
			return purl.Name, nil
		}
		_, image, found := strings.Cut(ru, "/")
		if !found {
			return "", fmt.Errorf("invalid repository_url for OCI pURL type %s", purl.String())
		}
		return image, nil
	case packageurl.TypeRPM:
		return purl.Name, nil
	default:
		return "", fmt.Errorf("unexpected purl type %s", purl.Type)
	}
}

var acceptedTypes = map[string]bool{
	packageurl.TypeOCI: true,
	packageurl.TypeRPM: true,
}

// CheckPURL checks if purl is something we're interested in.
//  1. Check the purl.Type is in the acceptable types.
//  2. Check if an advisory related to the kernel.
//  3. Check that all RPMs are in the "redhat" namespace.
func checkPURL(purl packageurl.PackageURL) bool {
	if ok := acceptedTypes[purl.Type]; !ok {
		return false
	}
	if strings.HasPrefix(purl.Name, "kernel") {
		// We don't want to ingest kernel advisories as
		// containers have no say in the kernel.
		return false
	}
	if purl.Type == packageurl.TypeRPM && purl.Namespace != "redhat" {
		// Not Red Hat rpm content.
		return false
	}
	return true
}

func extractArch(purl packageurl.PackageURL) string {
	arch := purl.Qualifiers.Map()["arch"]
	switch arch {
	case "amd64", "x86_64":
		return "amd64|x86_64"
	default:
		return arch
	}
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
