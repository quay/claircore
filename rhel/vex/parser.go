package vex

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"iter"
	"log/slog"
	"maps"
	"math"
	"net/url"
	"slices"
	"strings"
	"sync"
	"unique"

	"github.com/klauspost/compress/snappy"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/toolkit/types/cvss"
)

// Parse implements [driver.Updater].
func (u *Updater) Parse(_ context.Context, _ io.ReadCloser) ([]*claircore.Vulnerability, error) {
	// NOOP
	return nil, errors.ErrUnsupported
}

// DeltaParse implements [driver.DeltaUpdater].
func (u *Updater) DeltaParse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, []string, error) {
	// This map is needed for deduplication purposes, the compressed CSAF data will include
	// entries that have been subsequently updated in the changes.
	out := map[string][]*claircore.Vulnerability{}
	deleted := []string{}

	p := NewParser()
	r := bufio.NewReader(snappy.NewReader(contents))
	sz := 0
	for b, err := r.ReadBytes('\n'); err == nil; b, err = r.ReadBytes('\n') {
		name, vs, err := p.parseDoc(ctx, b)
		switch {
		case err == nil && len(vs) != 0:
			out[name] = vs
			sz += len(vs)
		case err == nil && len(vs) == 0:
			fallthrough
		case err == errDeleted:
			sz -= len(out[name])
			delete(out, name)
			deleted = append(deleted, name)
		default:
			return nil, nil, err
		}
	}

	vulns := make([]*claircore.Vulnerability, 0, sz)
	for _, vs := range out {
		vulns = append(vulns, vs...)
	}
	return vulns, deleted, nil
}

// Parser parses individual RHEL CSAF/VEX documents into claircore vulnerabilities.
//
// It maintains internal caches for claircore objects (Repositories, Packages) that
// are derived from CPE and product tree data. These caches avoid redundant
// allocations when the same CPE or product appears across multiple CSAF documents.
// The CSAF documents themselves are not cached - each document is parsed
// independently.
//
// Reusing the same Parser instance across multiple documents is more efficient than
// creating a new one for each document.
type Parser struct {
	pc *productCache
	rc *repoCache
}

// NewParser creates a new Parser with initialised caches.
func NewParser() *Parser {
	return &Parser{
		pc: newProductCache(),
		rc: newRepoCache(),
	}
}

// Parse parses a single RHEL CSAF/VEX document and returns claircore vulnerabilities.
// The Parser's internal caches for claircore objects are reused, so parsing multiple
// documents avoids redundant allocations for shared CPEs and repositories.
func (p *Parser) Parse(ctx context.Context, doc []byte) ([]*claircore.Vulnerability, error) {
	_, vs, err := p.parseDoc(ctx, doc)
	switch err {
	case nil, errDeleted:
	default:
		return nil, err
	}
	return vs, nil
}

// ErrDeleted is used to signal that a document has been set to status
// "deleted".
var errDeleted = errors.New("deleted")

// ParseDoc is the common code for [Parser.Parse] and [Updater.DeltaParse].
//
// This function always reports the document's tracking ID, if known.
//
// Is the documented is marked as "deleted", [errDeleted] is reported.
func (p *Parser) parseDoc(ctx context.Context, doc []byte) (string, []*claircore.Vulnerability, error) {
	c, err := csaf.Parse(bytes.NewReader(doc))
	if err != nil {
		return "", nil, fmt.Errorf("error parsing CSAF: %w", err)
	}

	name := c.Document.Tracking.ID
	if c.Document.Tracking.Status == "deleted" {
		return name, nil, errDeleted
	}

	var selfLink string
	for _, r := range c.Document.References {
		if r.Category == "self" {
			selfLink = r.URL
		}
	}

	creator := newCreator(name, selfLink, c, p.pc, p.rc)
	var out []*claircore.Vulnerability
	for _, v := range c.Vulnerabilities {
		links := []string{}
		for _, r := range v.References {
			links = append(links, r.URL)
		}
		links = append(links, selfLink)

		var desc string
		for _, n := range v.Notes {
			if n.Category == "description" {
				desc = n.Text
			}
		}

		protoVuln := func() *claircore.Vulnerability {
			return &claircore.Vulnerability{
				Updater:            "rhel-vex",
				Name:               name,
				Description:        desc,
				Issued:             v.ReleaseDate,
				Links:              strings.Join(links, " "),
				Severity:           "Unknown",
				NormalizedSeverity: claircore.Unknown,
			}
		}

		fixedVulns, err := creator.fixedVulnerabilities(ctx, v, protoVuln)
		if err != nil {
			return name, nil, err
		}
		out = append(out, fixedVulns...)

		knownAffectedVulns, err := creator.knownAffectedVulnerabilities(ctx, v, protoVuln)
		if err != nil {
			return name, nil, err
		}
		out = append(out, knownAffectedVulns...)
	}

	return name, out, nil
}

// repoCacheKey is a unique identifier for a repository, it is made
// to be used as a unique.Handle, hence the string fields.
type repoCacheKey struct {
	CPEString string
	RepoKey   string
}

// repoCache keeps a cache of all seen claircore.Repository objects.
type repoCache struct {
	cache map[unique.Handle[repoCacheKey]]*claircore.Repository
}

// NewRepoCache returns a repoCache with the backing map instantiated.
func newRepoCache() *repoCache {
	return &repoCache{
		cache: make(map[unique.Handle[repoCacheKey]]*claircore.Repository),
	}
}

// Get attempts to find a repo in the cache identified by a WFN and
// the repoKey. If it isn't found a repo is created and returned.
func (rc *repoCache) Get(cpe cpe.WFN, repoKey string) *claircore.Repository {
	rck := repoCacheKey{CPEString: cpe.String(), RepoKey: repoKey}
	k := unique.Make(rck)
	if r, ok := rc.cache[k]; ok {
		return r
	}
	r := &claircore.Repository{
		CPE:  cpe,
		Name: cpe.String(),
		Key:  repoKey,
	}
	rc.cache[k] = r
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
		vulnName: vulnName,
		vulnLink: vulnLink,
		c:        c,
		pc:       pc,
		rc:       rc,
	}
}

// creator attempts to lessen the memory burden when creating vulnerability objects
// by caching objects that are used multiple times during prcessing.
type creator struct {
	vulnName, vulnLink string
	c                  *csaf.CSAF
	pc                 *productCache
	rc                 *repoCache
}

func (c *creator) Status(ctx context.Context, v *csaf.Vulnerability, which string) iter.Seq2[status, error] {
	unrelatedProductIDs := []string{}
	log := slog.With("link", c.vulnLink)
	debugEnabled := log.Enabled(ctx, slog.LevelDebug)

	return func(yield func(status, error) bool) {
		productIDs := v.ProductStatus[which]
		for _, id := range productIDs {
			log := log.With("id", id)
			pkgID, _, repoID, err := c.c.WalkRelationships(id)
			if err != nil {
				if !yield(status{}, err) {
					return
				}
				continue
			}
			if repoID == "" {
				// It's possible to get here due to middleware not having a defined component:package
				// relationship. RHEL VEX requires products to have relationships.
				if debugEnabled {
					unrelatedProductIDs = append(unrelatedProductIDs, id)
				}
				continue
			}

			pkg := c.pc.Get(pkgID, c.c)
			repo := c.pc.Get(repoID, c.c)
			if repo == nil || pkg == nil {
				// Should never get here, error in data
				log.WarnContext(ctx, "could not find product(s) in product tree",
					slog.Group("package", "id", pkgID, "found", pkg != nil),
					slog.Group("repo", "id", repoID, "found", repo != nil),
				)
				continue
			}

			var purl *packageurl.PackageURL
			var wfn *cpe.WFN
			if s, ok := repo.IdentificationHelper["cpe"]; ok {
				v, err := cpe.Unbind(s)
				if err != nil {
					if !yield(status{}, err) {
						return
					}
					continue
				}
				wfn = &v
			}
			if s, ok := pkg.IdentificationHelper["purl"]; ok {
				v, err := packageurl.FromString(s)
				if err != nil {
					if !yield(status{}, err) {
						return
					}
					continue
				}
				purl = &v
			}
			if purl == nil || wfn == nil {
				// Should never get here, error in data
				log.WarnContext(ctx, "could not find needed identification helpers",
					slog.Group("package", "id", pkgID, "helper", "purl", "found", purl != nil),
					slog.Group("repo", "id", repoID, "helper", "cpe", "found", wfn != nil),
				)
				continue
			}
			if !checkPURL(*purl) {
				continue
			}

			score := c.c.FindScore(id)
			threat := c.c.FindThreat(id, "impact")
			if threat == nil && score != nil && cvssBaseScoreFromScore(score) == 0.0 {
				// This has no threat object and a 0.0 Base score: disregard.
				continue
			}
			remediation := c.c.FindRemediation(id)

			// Do fixups for specific statuses:
			switch which {
			case csaf.ProductStatusKnownNotAffected:
				purl.Version = ""
				purl.Qualifiers = slices.DeleteFunc(purl.Qualifiers, func(q packageurl.Qualifier) bool {
					return q.Key == "epoch" || q.Key == "tag"
				})
			}
			st := status{
				ID:           id,
				PackageID:    pkgID,
				RepositoryID: repoID,
				PURL:         *purl,
				WFN:          *wfn,
				Score:        score,
				Threat:       threat,
				Remediation:  remediation,
			}
			if !yield(st, nil) {
				return
			}
		}
	}
}

type status struct {
	ID           string
	PackageID    string
	RepositoryID string
	PURL         packageurl.PackageURL
	WFN          cpe.WFN
	Score        *csaf.Score
	Threat       *csaf.ThreatData
	Remediation  *csaf.RemediationData
}

func (s *status) PackageName() (string, error) {
	return extractPackageName(s.PURL)
}

func (s *status) FixedInVersion() (string, error) {
	return extractFixedInVersion(s.PURL)
}

func (s *status) Module() (string, error) {
	return componentPURLToModuleName(s.PURL)
}

func (s *status) Key() uint64 {
	h := getHasher()
	defer putHasher(h)

	// The purl is normalized when constructed, so this should all be stable:
	h.WriteString(s.PURL.Type)
	h.WriteString(s.PURL.Name)
	h.WriteString(s.PURL.Namespace)
	h.WriteString(s.PURL.Subpath)
	// Type specific shenanigans around the Version:
	switch s.PURL.Type {
	case packageurl.TypeOCI: // Skip
	default:
		h.WriteString(s.PURL.Version)
	}
	for _, q := range s.PURL.Qualifiers {
		switch q.Key {
		case "arch":
			continue
		default:
		}
		h.WriteString(q.Key)
		h.WriteString(q.Value)
	}

	// A little ad-hoc hashing scheme for the WFN.
	for _, a := range s.WFN.Attr {
		switch a.Kind {
		case cpe.ValueUnset:
			h.WriteByte(0x00)
		case cpe.ValueNA:
			h.WriteByte(0x01)
		case cpe.ValueAny:
			h.WriteByte(0x02)
		case cpe.ValueSet:
			h.WriteByte(0xFF)
			h.WriteString(a.V)
		}
	}

	return h.Sum64()
}

var (
	seed     = maphash.MakeSeed()
	hashPool = sync.Pool{
		New: func() any {
			h := new(maphash.Hash)
			h.SetSeed(seed)
			return h
		},
	}
)

func getHasher() *maphash.Hash {
	return hashPool.Get().(*maphash.Hash)
}

func putHasher(h *maphash.Hash) {
	h.Reset()
	hashPool.Put(h)
}

// Note: Relationship walking is now handled by csaf.CSAF.WalkRelationships().
// RHEL VEX requires products to have relationships (package -> repo), so callers
// must check for empty repoProductID after calling WalkRelationships.

// KnownAffectedVulnerabilities processes the "known_affected" array of products
// in the VEX object.
func (c *creator) knownAffectedVulnerabilities(ctx context.Context, v csaf.Vulnerability, protoVulnFunc func() *claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	out := []*claircore.Vulnerability{}
	for st, err := range c.Status(ctx, &v, csaf.ProductStatusKnownAffected) {
		if err != nil {
			return nil, err
		}

		vuln := protoVulnFunc()
		pkgName, err := st.PackageName()
		if err != nil {
			return nil, err
		}
		modName, err := st.Module()
		if err != nil {
			return nil, err
		}
		vuln.Package = &claircore.Package{
			Name:   pkgName,
			Kind:   types.SourcePackage, // Always source?
			Module: modName,
		}
		if sc := st.Score; sc != nil {
			vuln.Severity, err = cvssVectorFromScore(sc)
			if err != nil {
				return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.vulnLink)
			}
		}
		if t := st.Threat; t != nil {
			vuln.NormalizedSeverity = common.NormalizeSeverity(t.Details)
		}

		switch st.PURL.Type {
		case packageurl.TypeOCI:
			vuln.Repo = c.rc.Get(st.WFN, rhcc.RepositoryKey)
			vuln.Range = &claircore.Range{
				Lower: new(rhctag.Version).Version(true),
				Upper: (&rhctag.Version{
					Major: math.MaxInt32, // Everything is vulnerable
				}).Version(true),
			}
		case packageurl.TypeRPM:
			vuln.Repo = c.rc.Get(st.WFN, st.RepositoryID)
		}

		// Append VEX product ID as URL fragment to the last link for downstream comparison.
		if vuln.Links != "" {
			vuln.Links = vuln.Links + "#" + url.PathEscape(st.ID)
		}
		out = append(out, vuln)
	}

	return out, nil
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
	rng := &claircore.Range{}

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

// ResetLowest zeros out all the lowest versions' lower bounds
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
	log := slog.With("link", c.vulnLink)
	vmap := make(map[uint64]*claircore.Vulnerability)

	for st, err := range c.Status(ctx, &v, csaf.ProductStatusFixed) {
		if err != nil {
			return nil, err
		}

		key := st.Key()
		vuln, exists := vmap[key]
		if !exists {
			fixedIn, err := st.FixedInVersion()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", &st.PURL, "missing", "FixedInVersion")
				continue
			}
			pkgName, err := st.PackageName()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", &st.PURL, "missing", "PackageName")
				continue
			}
			modName, err := st.Module()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", &st.PURL, "missing", "ModuleName")
				continue
			}
			sev, err := cvssVectorFromScore(st.Score)
			if err != nil {
				log.WarnContext(ctx, "bad score", "reason", err, "found", st.Score != nil)
				continue
			}

			vuln = protoVulnFunc()
			vuln.FixedInVersion = fixedIn
			vuln.Package = &claircore.Package{
				Name:   pkgName,
				Kind:   types.BinaryPackage,
				Module: modName,
			}
			vuln.Severity = sev
			if t := st.Threat; t != nil {
				vuln.NormalizedSeverity = common.NormalizeSeverity(t.Details)
			}
			switch st.PURL.Type {
			case packageurl.TypeRPM:
				vuln.Repo = c.rc.Get(st.WFN, repoKey)
			case packageurl.TypeOCI:
				vuln.Repo = c.rc.Get(st.WFN, rhcc.RepositoryKey)
				vuln.Range, err = ranger.add(st.PURL.Name, vuln.FixedInVersion)
				if err != nil {
					log.WarnContext(ctx, "could not parse version into range",
						"reason", err, "version", vuln.FixedInVersion)
					continue
				}
			default:
				panic("unreachable")
			}
			// Find remediations and add RHSA URL to links
			if rem := st.Remediation; rem != nil {
				vuln.Links = vuln.Links + " " + rem.URL
			}
			// Append VEX product ID as URL fragment to the last link for downstream comparison.
			if vuln.Links != "" {
				vuln.Links = vuln.Links + "#" + url.PathEscape(st.ID)
			}

			vmap[key] = vuln
		}
		if arch := extractArch(st.PURL); arch != "" {
			if vuln.Package.Arch == "" {
				vuln.Package.Arch = arch
				vuln.ArchOperation = claircore.OpPatternMatch
			} else {
				vuln.Package.Arch = vuln.Package.Arch + "|" + arch
			}
		}
	}
	ranger.resetLowest()

	out := slices.Collect(maps.Values(vmap))
	slices.SortFunc(out, func(a, b *claircore.Vulnerability) int {
		return strings.Compare(a.Links, b.Links)
	})
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

// componentPURLToModuleName extracts the module name from the component PURL.
func componentPURLToModuleName(purl packageurl.PackageURL) (string, error) {
	v, ok := purl.Qualifiers.Map()["rpmmod"]
	if !ok {
		return "", nil
	}
	if v == "" {
		return "", fmt.Errorf("empty rpmmod in pURL qualifiers %s", purl.String())
	}
	name, rest, ok := strings.Cut(v, ":")
	if !ok || rest == "" {
		return "", fmt.Errorf("invalid module name in pURL qualifiers %s", purl.String())
	}
	stream, _, _ := strings.Cut(rest, ":")
	if stream == "" {
		return "", fmt.Errorf("invalid module stream in pURL qualifiers %s", purl.String())
	}
	return name + ":" + stream, nil
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
		if purl.Version == "" {
			return "", nil
		}
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
	for i := range c {
		if strings.HasSuffix(c[i], "*") {
			c[i] = c[i][:len(c[i])-1] + `%02`
		}
		c[i] = strings.ReplaceAll(c[i], "?", "%01")
	}
	return strings.Join(c, ":")
}
