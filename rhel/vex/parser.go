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
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/toolkit/types/cvss"
)

// Parse implements [driver.Updater].
func (u *VEXUpdater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	// NOOP
	return nil, errors.ErrUnsupported
}

// DeltaParse implements [driver.DeltaUpdater].
func (u *VEXUpdater) DeltaParse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, []string, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/VEXUpdater.DeltaParse")
	// This map is needed for deduplication purposes, the compressed CSAF data maybe include
	// entries that have been subsequently updated in the changes.
	out := map[string][]*claircore.Vulnerability{}

	pc := NewProductCache()

	r := bufio.NewReader(snappy.NewReader(contents))
	for b, err := r.ReadBytes('\n'); err == nil; b, err = r.ReadBytes('\n') {
		c, err := csaf.Parse(bytes.NewReader(b))
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing CSAF: %w", err)
		}
		name := c.Document.Tracking.ID

		var selfLink string
		for _, r := range c.Document.References {
			if r.Category == "self" {
				selfLink = r.URL
			}
		}
		ctx = zlog.ContextWithValues(ctx, "link", selfLink)
		creator := NewCreator(name, selfLink, c, pc)
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
			// TODO: respect updater option to skip unpatched vulnerabilities
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

	return vulns, nil, nil
}

type productCache struct {
	cache map[string]*csaf.Product
}

func NewProductCache() *productCache {
	return &productCache{
		cache: make(map[string]*csaf.Product),
	}
}

func (pc *productCache) Get(c *csaf.CSAF, productID string) *csaf.Product {
	if p, ok := pc.cache[productID]; ok {
		return p
	}
	p := c.ProductTree.FindProductByID(productID)
	pc.cache[productID] = p
	return p

}

func NewCreator(vulnName, vulnLink string, c *csaf.CSAF, pc *productCache) *creator {
	return &creator{
		vulnName:       vulnName,
		vulnLink:       vulnLink,
		uniqueVulnsIdx: make(map[string]int),
		pc:             pc,
		c:              c,
	}
}

type creator struct {
	vulnName, vulnLink string
	uniqueVulnsIdx     map[string]int
	fixedVulns         []claircore.Vulnerability
	c                  *csaf.CSAF
	pc                 *productCache
}

func (c *creator) knownAffectedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	// Known affected
	out := []*claircore.Vulnerability{}
	for _, pc := range v.ProductStatus["known_affected"] {
		rel := c.c.ProductTree.Relationships.FindRelationship(pc, "default_component_of")
		if rel == nil {
			// Should never get here, error in data
			zlog.Debug(ctx).
				Str("product:package", pc).
				Msg("could not find a relationship for product:package")
			continue
		}
		if strings.HasPrefix(rel.ProductRef, "kernel") {
			// We don't want to ingest kernel advisories as
			// containers have no say in the kernel.
			continue
		}
		repoProd := c.pc.Get(c.c, rel.RelatesToProductRef)
		if repoProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("prod", rel.RelatesToProductRef).
				Msg("could not find product in product tree")
			continue
		}
		cpeHelper, ok := repoProd.IdentificationHelper["cpe"]
		if !ok {
			zlog.Warn(ctx).
				Str("prod", rel.RelatesToProductRef).
				Msg("could not find cpe helper type in product")
			continue
		}

		vuln := protoVulnFunc()
		// What is the deal here? Just stick the package name in and f-it?
		// That's the plan so far as there's no PURL product ID helper.
		vuln.Package = &claircore.Package{
			Name: rel.ProductRef,
			Kind: claircore.SOURCE,
		}

		wfn, err := cpe.Unbind(cpeHelper)
		if err != nil {
			return nil, fmt.Errorf("could not unbind cpe: %s %w", cpeHelper, err)
		}
		vuln.Repo = &claircore.Repository{
			CPE:  wfn,
			Name: cpeHelper,
			Key:  repoKey,
		}
		if sc := c.c.FindScore(pc); sc != nil {
			vuln.NormalizedSeverity, vuln.Severity, err = CVSSVectorFromScore(sc)
			if err != nil {
				return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.vulnLink)
			}
		}
		out = append(out, vuln)
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

func (c *creator) fixedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	for _, pc := range v.ProductStatus["fixed"] {
		rel := c.c.FindRelationship(pc, "default_component_of")
		if rel == nil {
			// We can get here, it means we don't have a repo:pkg relationship.
			// In our case, this information is not useful, so skip.
			continue
		}
		repoProd := c.pc.Get(c.c, rel.RelatesToProductRef)
		if repoProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("prod", rel.RelatesToProductRef).
				Msg("could not find product in product tree")
			continue
		}
		cpeHelper, ok := repoProd.IdentificationHelper["cpe"]
		if !ok {
			zlog.Warn(ctx).
				Str("prod", rel.RelatesToProductRef).
				Msg("could not find cpe helper type in product")
			continue
		}
		compProd := c.pc.Get(c.c, rel.ProductRef)
		if compProd == nil {
			// Should never get here, error in data
			zlog.Warn(ctx).
				Str("pkg", rel.ProductRef).
				Msg("could not find package in product tree")
			continue
		}
		purlHelper, ok := compProd.IdentificationHelper["purl"]
		if !ok {
			zlog.Warn(ctx).
				Str("pkg", rel.ProductRef).
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
		vulnKey := createPackageKey(rel.RelatesToProductRef, purl.Name, fixedIn)
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
				// TODO (crozzy): Check we're always pattern matching
				vuln.ArchOperation = claircore.OpPatternMatch
			}

			wfn, err := cpe.Unbind(cpeHelper)
			if err != nil {
				return nil, fmt.Errorf("could not unbind cpe: %s %w", cpeHelper, err)
			}
			vuln.Repo = &claircore.Repository{
				// It _feels_ more correct to match on the CPE
				// field here, double check the matcher logic.
				CPE:  wfn,
				Name: cpeHelper,
				Key:  repoKey,
			}
			// Find remediations and add RHSA URL to links
			rem := c.c.FindRemediation(pc)
			if rem != nil {
				vuln.Links = vuln.Links + " " + rem.URL
			}
			if sc := c.c.FindScore(pc); sc != nil {
				vuln.NormalizedSeverity, vuln.Severity, err = CVSSVectorFromScore(sc)
				if err != nil {
					return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.vulnLink)
				}
			}
		}
	}
	out := make([]*claircore.Vulnerability, len(c.fixedVulns))
	for i := range c.fixedVulns {
		out[i] = &c.fixedVulns[i]
	}
	return out, nil
}

func CVSSVectorFromScore(sc *csaf.Score) (sev claircore.Severity, vec string, err error) {
	switch {
	case sc.CVSSV4 != nil:
		var c cvss.V4
		c, err = cvss.ParseV4(sc.CVSSV4.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		sev = CVSS2ClaircoreSeverity(cvss.QualitativeScore[cvss.V4Metric](&c))
		vec = sc.CVSSV4.VectorString
		return
	case sc.CVSSV3 != nil:
		var c cvss.V3
		c, err = cvss.ParseV3(sc.CVSSV3.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv3 vector string %w", err)
			return
		}
		sev = CVSS2ClaircoreSeverity(cvss.QualitativeScore[cvss.V3Metric](&c))
		vec = sc.CVSSV3.VectorString
		return
	case sc.CVSSV2 != nil:
		var c cvss.V2
		c, err = cvss.ParseV2(sc.CVSSV2.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		sev = CVSS2ClaircoreSeverity(cvss.QualitativeScore[cvss.V2Metric](&c))
		vec = sc.CVSSV2.VectorString
		return
	default:
		err = errors.New("could not find a valid CVSS object")
	}
	return
}

// CVSS2ClaircoreSeverity returns a claircore.Severity given a cvss.Qualitative
// It will panic if asked to reason with an unknown Qualitative score.
func CVSS2ClaircoreSeverity(q cvss.Qualitative) claircore.Severity {
	s, ok := CVSS2ClaircoreSeverityMap[q]
	if !ok {
		panic("unmappable cvss.Qualitative score")
	}
	return s
}

var CVSS2ClaircoreSeverityMap = map[cvss.Qualitative]claircore.Severity{
	cvss.None:     claircore.Unknown,
	cvss.Low:      claircore.Low,
	cvss.Medium:   claircore.Medium,
	cvss.High:     claircore.High,
	cvss.Critical: claircore.Critical,
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
