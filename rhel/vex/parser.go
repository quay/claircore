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
	"math"
	"net/url"
	"path"
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
	product          *productIndex
	rc               *repoCache
	score            *scoreIndex
	threatImpact     *threatImpactIndex
	remediation      *remediationIndex
	defaultComponent *defaultComponentIndex
}

// NewParser creates a new Parser with initialised caches.
func NewParser() *Parser {
	return &Parser{
		product:          newProductIndex(),
		rc:               newRepoCache(),
		score:            newScoreIndex(),
		threatImpact:     newThreatImpactIndex(),
		remediation:      newRemediationIndex(),
		defaultComponent: newDefaultComponentIndex(),
	}
}

// Parse parses a single RHEL CSAF/VEX document and returns claircore vulnerabilities.
// The Parser's internal caches for claircore objects are reused, so parsing multiple
// documents avoids redundant allocations for shared CPEs and repositories.
//
// A Parser is not safe for concurrent use.
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
// If the documented is marked as "deleted", [errDeleted] is reported.
func (p *Parser) parseDoc(ctx context.Context, doc []byte) (string, []*claircore.Vulnerability, error) {
	c, err := csaf.Parse(bytes.NewReader(doc))
	if err != nil {
		return "", nil, fmt.Errorf("error parsing CSAF: %w", err)
	}

	name := c.Document.Tracking.ID
	if c.Document.Tracking.Status == "deleted" {
		return name, nil, errDeleted
	}

	creator := p.creator(name, c)
	var out []*claircore.Vulnerability
	for i := range c.Vulnerabilities {
		v := &c.Vulnerabilities[i]
		issued := v.ReleaseDate
		var selfAlias claircore.Alias
		cveAlias, err := cveToAlias(v.CVE)
		if err != nil {
			return name, nil, err
		}
		aliases := []claircore.Alias{
			cveAlias,
		}
		links := make([]string, 0, len(v.References)+1)
		for _, r := range v.References {
			links = append(links, r.URL)
			switch r.Category {
			case "self":
				selfAlias.Space = spaceRedHat
				selfAlias.Name = v.CVE
			case "external":
				switch {
				case strings.HasPrefix(r.URL, `https://bugzilla.redhat.com/`):
					if _, id, ok := strings.Cut(r.URL, `id=`); ok {
						aliases = append(aliases, claircore.Alias{Space: spaceRHBZ, Name: id})
					}
				case strings.HasPrefix(r.URL, `https://pkg.go.dev/vuln/`):
					id := path.Base(r.URL)
					if ns, id, ok := strings.Cut(id, "-"); ok && ns == "GO" {
						aliases = append(aliases, claircore.Alias{Space: spaceGo, Name: id})
					}
				}
			}
		}
		if creator.docLink != "" {
			links = append(links, creator.docLink)
		}

		var desc string
		for _, n := range v.Notes {
			if n.Category == "description" {
				desc = n.Text
			}
		}

		initVuln := func(_ context.Context, v *claircore.Vulnerability) error {
			v.Updater = "rhel-vex"
			v.Name = name
			v.Description = desc
			v.Issued = issued
			v.Links = strings.Join(links, " ")
			v.Severity = "Unknown"
			v.NormalizedSeverity = claircore.Unknown
			v.Self = selfAlias
			v.Aliases = aliases
			return nil
		}

		fixedVulns, err := creator.fixedVulnerabilities(ctx, v, initVuln)
		if err != nil {
			return name, nil, err
		}
		out = append(out, fixedVulns...)

		knownAffectedVulns, err := creator.knownAffectedVulnerabilities(ctx, v, initVuln)
		if err != nil {
			return name, nil, err
		}
		out = append(out, knownAffectedVulns...)

		knownNotAffectedVulns, err := creator.knownNotAffectedVulnerabilities(ctx, v, initVuln)
		if err != nil {
			return name, nil, err
		}
		out = append(out, knownNotAffectedVulns...)
	}
	creator.SkipLog(ctx)

	return name, out, nil
}

// BUG(hank) The RHBZ space is somewhat arbitrary. Might be worth doing a little
// survey of what references are used in the VEX data.
var (
	spaceRedHat = unique.Make("https://access.redhat.com/security/cve/")
	spaceCVE    = unique.Make(`CVE`)
	spaceRHBZ   = unique.Make(`RHBZ`)
	spaceGo     = unique.Make(`GO`)
)

func cveToAlias(s string) (claircore.Alias, error) {
	space, id, ok := strings.Cut(s, "-")
	if !ok || space != `CVE` {
		return claircore.Alias{}, fmt.Errorf("vex: malformed CVE ID: %q", s)
	}
	return claircore.Alias{
		Space: spaceCVE,
		Name:  id,
	}, nil
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
func (rc *repoCache) Get(cpe *cpe.WFN, repoKey string) *claircore.Repository {
	rck := repoCacheKey{CPEString: cpe.String(), RepoKey: repoKey}
	k := unique.Make(rck)
	if r, ok := rc.cache[k]; ok {
		return r
	}
	r := &claircore.Repository{
		CPE:  *cpe,
		Name: cpe.String(),
		Key:  repoKey,
	}
	rc.cache[k] = r
	return r
}

func (p *Parser) creator(name string, doc *csaf.CSAF) *creator {
	p.product.Reset(doc)
	p.score.Reset(doc)
	p.threatImpact.Reset(doc)
	p.remediation.Reset(doc)
	p.defaultComponent.Reset(doc)
	var selfLink string
	for _, r := range doc.Document.References {
		if r.Category == "self" {
			selfLink = r.URL
		}
	}
	return &creator{
		docName:          name,
		docLink:          selfLink,
		c:                doc,
		product:          p.product,
		rc:               p.rc,
		score:            p.score,
		threatImpact:     p.threatImpact,
		remediation:      p.remediation,
		defaultComponent: p.defaultComponent,
		skip:             make(map[string]skipReason),
	}
}

// Creator attempts to lessen the memory burden when creating vulnerability objects
// by caching objects that are used multiple times during processing.
type creator struct {
	docName, docLink string
	skip             map[string]skipReason
	c                *csaf.CSAF
	product          *productIndex
	rc               *repoCache
	score            *scoreIndex
	threatImpact     *threatImpactIndex
	remediation      *remediationIndex
	defaultComponent *defaultComponentIndex
}

// SkipReason records the reason a "product_id" is going to be skipped for the
// rest of a run.
type skipReason byte

const (
	_ skipReason = iota
	// No such "relationship", or it doesn't resolve correctly.
	skipBadRelation
	// The CSAF "product" is not suitable to interpret as a "package".
	skipBadPackage
	// The CSAF "product" is not suitable to interpret as a "repository".
	skipBadRepository
)

// SkipLog logs information about skipped product_ids.
func (c *creator) SkipLog(ctx context.Context) {
	log := slog.With("link", c.docLink)
	if !log.Enabled(ctx, slog.LevelDebug) || len(c.skip) == 0 {
		return
	}
	sz := len(c.skip)
	rel, pkg, repo := make([]string, 0, sz), make([]string, 0, sz), make([]string, 0, sz)
	for id, k := range c.skip {
		switch k {
		case skipBadRelation:
			rel = append(rel, id)
		case skipBadPackage:
			pkg = append(pkg, id)
		case skipBadRepository:
			repo = append(repo, id)
		default:
			panic("unreachable")
		}
	}
	attrs := make([]slog.Attr, 0, 3)
	if len(rel) != 0 {
		attrs = append(attrs, slog.Any("relation", rel))
	}
	if len(pkg) != 0 {
		attrs = append(attrs, slog.Any("package", pkg))
	}
	if len(repo) != 0 {
		attrs = append(attrs, slog.Any("repository", repo))
	}
	log.LogAttrs(ctx, slog.LevelDebug, "skipped product_ids", attrs...)
}

// Status returns an iterator over the products in "v" with the status "which".
//
// Entries that are "structurally malformed" (e.g. has an invalid CPE Name or
// has a dangling "product_id" reference) cause the iterator to yield an error.
// Entries that are not usable but not malformed are silently skipped.
func (c *creator) Status(ctx context.Context, v *csaf.Vulnerability, which string) iter.Seq2[status, error] {
	log := slog.With("link", c.docLink)
	return func(yield func(status, error) bool) {
		productIDs := v.ProductStatus[which]
		for _, id := range productIDs {
			if _, ok := c.skip[id]; ok {
				continue
			}
			log := log.With("id", id)
			rel := c.defaultComponent.Get(id)
			if rel == nil {
				// It's possible to get here due to middleware not having a
				// defined component-to-package relationship. RHEL VEX requires
				// products to have relationships.
				c.skip[id] = skipBadRelation
				continue
			}
			const relMax = 5
			var relDepth int
			var pkgID, repoID string
			for pkgID, relDepth = rel.ProductRef, 0; relDepth < relMax; relDepth++ {
				r := c.defaultComponent.Get(pkgID)
				if r == nil {
					break
				}
				pkgID = r.ProductRef
			}
			for repoID, relDepth = rel.RelatesToProductRef, 0; relDepth < relMax; relDepth++ {
				r := c.defaultComponent.Get(repoID)
				if r == nil {
					break
				}
				repoID = r.RelatesToProductRef
			}
			if _, ok := c.skip[pkgID]; ok {
				continue
			}
			if _, ok := c.skip[repoID]; ok {
				continue
			}

			pkg := c.product.Get(pkgID)
			repo := c.product.Get(repoID)
			if repo == nil || pkg == nil {
				// Should never get here, error in data.
				log.WarnContext(ctx, "could not find product(s) in product tree",
					slog.Group("package", "id", pkgID, "found", pkg != nil),
					slog.Group("repo", "id", repoID, "found", repo != nil),
				)
				if pkg == nil {
					c.skip[pkgID] = skipBadPackage
				}
				if repo == nil {
					c.skip[repoID] = skipBadRepository
				}
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
				// Should never get here, error in data.
				log.WarnContext(ctx, "could not find needed identification helpers",
					slog.Group("package", "id", pkgID, "helper", "purl", "found", purl != nil),
					slog.Group("repo", "id", repoID, "helper", "cpe", "found", wfn != nil),
				)
				if purl == nil {
					c.skip[pkgID] = skipBadPackage
				}
				if wfn == nil {
					c.skip[repoID] = skipBadRepository
				}
				continue
			}
			if !checkPURL(purl) { // Not a usable purl.
				continue
			}

			score := c.score.Get(id)
			threat := c.threatImpact.Get(id)
			if threat == nil && score != nil && cvssBaseScoreFromScore(score) == 0.0 {
				// This has no threat object and a 0.0 Base score: disregard.
				continue
			}
			remediation := c.remediation.Get(id)

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
				PURL:         purl,
				WFN:          wfn,
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

// Status is an individual "product status" that's well-formed according to Red
// Hat's guidelines.
//
// [Score], [Threat], and [Remediation] may be nil, but [PURL] and [WFN] will
// not be.
type status struct {
	ID           string
	PackageID    string
	RepositoryID string
	PURL         *packageurl.PackageURL
	WFN          *cpe.WFN
	Score        *csaf.Score
	Threat       *csaf.ThreatData
	Remediation  *csaf.RemediationData
}

// PacakgeName reports the package name and any error encountered while trying
// to determine it.
//
// Will not be an empty string if the returned [error] is nil.
func (s *status) PackageName() (string, error) {
	return extractPackageName(s.PURL)
}

// FixedInVersion reports the "fixed in" version and any error encountered while
// trying to determine it.
//
// May be an empty string even if the returned [error] is nil.
func (s *status) FixedInVersion() (string, error) {
	return extractFixedInVersion(s.PURL)
}

// Module reports the module name and any error encountered while trying to
// determine it.
//
// May be an empty string even if the returned [error] is nil.
func (s *status) Module() (string, error) {
	return componentPURLToModuleName(s.PURL)
}

// Key returns a local-process-only unique integer.
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
	hashPool = sync.Pool{}
)

func getHasher() *maphash.Hash {
	v := hashPool.Get()
	if v == nil {
		h := new(maphash.Hash)
		h.SetSeed(seed)
		return h
	}
	return v.(*maphash.Hash)
}

func putHasher(h *maphash.Hash) {
	h.Reset()
	hashPool.Put(h)
}

// VulnHook is the type used to modify the passed [*claircore.Vulnerability].
//
// Reporting an error should cause the calling function to error immediately.
type vulnHook func(context.Context, *claircore.Vulnerability) error

// VulnCmp is used to sort slices of [claircore.Vulnerability].
func vulnCmp(a, b *claircore.Vulnerability) int {
	return strings.Compare(a.Links, b.Links)
}

// Rope provides an ordered collection of E values with minimal copying.
//
// This is done by building a slice of slices and only returning pointers into
// it. This implementation only allows the "tail" of the rope to be modified. To
// iterate over the values, use the [All] method.
type rope[E any] [][]E

// New returns a pointer to value at the "end" of the rope.
func (r *rope[E]) New() *E {
	sp := (*[][]E)(r)
	// Make the zero value useful:
	if (*sp) == nil {
		*sp = make([][]E, 0, 64)
	}
	// Need to handle the initial segment specifically:
	if len(*sp) == 0 {
		*sp = append(*sp, make([]E, 0, 64))
	}
	// Make sure the segment has capacity:
GetSeg:
	cur := &(*sp)[len(*sp)-1]
	if len(*cur) == cap(*cur) {
		// Need to append a new segment.
		*sp = append(*sp, make([]E, 0, 64))
		goto GetSeg
	}
	// Extend by one element.
	i := len(*cur)
	*cur = (*cur)[:i+1]
	// Return the new element.
	return &(*cur)[i]
}

// Drop removes the element at the "end" of the rope by zeroing the value and
// manipulating the internal slices.
//
// SAFETY(hank) It's possible that this method can zero out values that still
// have live pointers. Be careful with a pointer from New until you're sure
// Drop won't be called.
func (r *rope[E]) Drop() {
	sp := (*[][]E)(r)

	sl := len(*sp)
	if sl == 0 {
		panic("programmer error: drop from empty rope")
	}
	cur := &(*sp)[sl-1]
	cl := len(*cur)
	if cl == 0 {
		panic("programmer error: empty segment")
	}
	// Zero the value:
	clear((*cur)[cl-1 : cl])
	// Slice off the last value.
	*cur = (*cur)[:cl-1]
	// Now check to see if the current segment is empty and needs to be sliced
	// off:
	if cl-1 == 0 {
		*sp = (*sp)[:sl-1]
	}
}

// All returns an iterator over all the elements in the rope.
func (r *rope[E]) All() iter.Seq[*E] {
	return func(yield func(*E) bool) {
		for _, seg := range *(*[][]E)(r) {
			for i := range seg {
				if !yield(&seg[i]) {
					return
				}
			}
		}
	}
}

// KnownAffectedVulnerabilities processes the "known_affected" array of products
// in the VEX object.
func (c *creator) knownAffectedVulnerabilities(ctx context.Context, v *csaf.Vulnerability, init vulnHook) ([]*claircore.Vulnerability, error) {
	var backing rope[claircore.Vulnerability]
	for st, err := range c.Status(ctx, v, csaf.ProductStatusKnownAffected) {
		if err != nil {
			return nil, err
		}

		// This loop never skips returned [status] values, so we can always just
		// append a new [claircore.Vulnerability].
		vuln := backing.New()

		if err := init(ctx, vuln); err != nil {
			return nil, err
		}
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
				return nil, fmt.Errorf("could not parse CVSS score: %w, file: %s", err, c.docLink)
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
			vuln.Repo = c.rc.Get(st.WFN, repoKey)
		}

		// Embed VEX product ID as a URL fragment on the VEX document self-link for downstream comparison.
		if c.docLink != "" {
			vuln.Links = strings.Replace(vuln.Links, c.docLink, c.docLink+"#"+url.PathEscape(st.ID), 1)
		}
	}

	out := slices.Collect(backing.All())
	slices.SortFunc(out, vulnCmp)
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
func (c *creator) fixedVulnerabilities(ctx context.Context, v *csaf.Vulnerability, init vulnHook) ([]*claircore.Vulnerability, error) {
	// This "ranger" indirection works because the [claircore.Vulnerability]
	// values contain pointers to [claircore.Range] values "owned" by the
	// ranger.
	ranger := newRanger()
	log := slog.With("link", c.docLink)
	var backing rope[claircore.Vulnerability]
	var doDrop bool
	vmap := make(map[uint64]*claircore.Vulnerability)
	lookup := func(key uint64) (*claircore.Vulnerability, bool) {
		if doDrop {
			backing.Drop()
			doDrop = false
		}
		v, exists := vmap[key]
		if !exists {
			v = backing.New()
			doDrop = true
		}
		return v, !exists
	}
	commit := func(key uint64, v *claircore.Vulnerability) {
		doDrop = false
		vmap[key] = v
	}

	for st, err := range c.Status(ctx, v, csaf.ProductStatusFixed) {
		if err != nil {
			return nil, err
		}

		key := st.Key()
		vuln, created := lookup(key)
		if created {
			fixedIn, err := st.FixedInVersion()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", st.PURL, "missing", "FixedInVersion")
				continue
			}
			pkgName, err := st.PackageName()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", st.PURL, "missing", "PackageName")
				continue
			}
			modName, err := st.Module()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", st.PURL, "missing", "ModuleName")
				continue
			}
			sev, err := cvssVectorFromScore(st.Score)
			if err != nil {
				log.WarnContext(ctx, "bad score", "reason", err, "found", st.Score != nil)
				continue
			}

			if err := init(ctx, vuln); err != nil {
				return nil, err
			}
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
			// Embed VEX product ID as a URL fragment on the VEX document self-link for downstream comparison.
			if c.docLink != "" {
				vuln.Links = strings.Replace(vuln.Links, c.docLink, c.docLink+"#"+url.PathEscape(st.ID), 1)
			}
			// Append RHSA URL after the VEX self-link.
			if rem := st.Remediation; rem != nil {
				vuln.Links = vuln.Links + " " + rem.URL
			}

			commit(key, vuln)
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
	// Catch if the last status bailed.
	if doDrop {
		backing.Drop()
	}
	// Modify ranges for the rhcc matcher.
	ranger.resetLowest()

	out := slices.Collect(backing.All())
	slices.SortFunc(out, vulnCmp)
	return out, nil
}

// KnownNotAffectedVulnerabilities processes the "known_not_affected" array of products
// in the VEX object.
func (c *creator) knownNotAffectedVulnerabilities(ctx context.Context, v *csaf.Vulnerability, init vulnHook) ([]*claircore.Vulnerability, error) {
	log := slog.With("link", c.docLink)
	var backing rope[claircore.Vulnerability]
	var doDrop bool
	vmap := make(map[uint64]*claircore.Vulnerability)
	lookup := func(key uint64) (*claircore.Vulnerability, bool) {
		if doDrop {
			backing.Drop()
			doDrop = false
		}
		v, exists := vmap[key]
		if !exists {
			v = backing.New()
			doDrop = true
		}
		return v, !exists
	}
	commit := func(key uint64, v *claircore.Vulnerability) {
		doDrop = false
		vmap[key] = v
	}

	for st, err := range c.Status(ctx, v, csaf.ProductStatusKnownNotAffected) {
		if err != nil {
			return nil, err
		}

		key := st.Key()
		vuln, created := lookup(key)
		if created {
			pkgName, err := st.PackageName()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", st.PURL, "missing", "PackageName")
				continue
			}
			modName, err := st.Module()
			if err != nil {
				log.WarnContext(ctx, "bad purl", "reason", err, "purl", st.PURL, "missing", "ModuleName")
				continue
			}

			if err := init(ctx, vuln); err != nil {
				return nil, err
			}
			vuln.Invert = true
			vuln.Package = &claircore.Package{
				Name:   pkgName,
				Kind:   types.BinaryPackage,
				Module: modName,
			}
			if sc := st.Score; sc != nil {
				s, err := cvssVectorFromScore(sc)
				if err != nil {
					log.WarnContext(ctx, "bad score", "reason", err, "found", true)
					continue
				}
				vuln.Severity = s
			}
			if t := st.Threat; t != nil {
				vuln.NormalizedSeverity = common.NormalizeSeverity(t.Details)
			}
			switch st.PURL.Type {
			case packageurl.TypeRPM:
				vuln.Repo = c.rc.Get(st.WFN, repoKey)
			case packageurl.TypeOCI:
				vuln.Repo = c.rc.Get(st.WFN, rhcc.RepositoryKey)
				vuln.Package.Kind = types.AncestryPackage
				// Use a flood-gates range that matches all versions. For
				// known_not_affected assertions, the package name match is
				// sufficient; the matcher skips version comparison when
				// Invert is true.
				vuln.Range = &claircore.Range{
					Lower: new(rhctag.Version).Version(true),
					Upper: (&rhctag.Version{
						Major: math.MaxInt32,
					}).Version(true),
				}
			default:
				panic("unreachable")
			}
			// Embed VEX product ID as a URL fragment on the VEX document self-link for downstream comparison.
			if c.docLink != "" {
				vuln.Links = strings.Replace(vuln.Links, c.docLink, c.docLink+"#"+url.PathEscape(st.ID), 1)
			}
			// Append RHSA URL after the VEX self-link.
			if rem := st.Remediation; rem != nil {
				vuln.Links = vuln.Links + " " + rem.URL
			}

			commit(key, vuln)
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
	// Catch if the last status bailed.
	if doDrop {
		backing.Drop()
	}

	out := slices.Collect(backing.All())
	slices.SortFunc(out, vulnCmp)
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
	case sc == nil:
		err = errors.New("no Score object")
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

// Qualifier returns the value of the indicated qualifier and whether it was
// found.
//
// Using this rather than the [packageurl.Qualifiers.Map] method exploits the
// fact that the [packageurl.Qualifiers] is sorted, so we don't need to
// construct a new map to do an efficient lookup.
func qualifier(p *packageurl.PackageURL, key string) (string, bool) {
	qs := p.Qualifiers
	cmp := func(q packageurl.Qualifier, key string) int {
		return strings.Compare(q.Key, key)
	}
	i, ok := slices.BinarySearchFunc(qs, key, cmp)
	if !ok {
		return "", false
	}
	return qs[i].Value, true
}

// componentPURLToModuleName extracts the module name from the component PURL.
func componentPURLToModuleName(p *packageurl.PackageURL) (string, error) {
	v, ok := qualifier(p, "rpmmod")
	if !ok {
		return "", nil
	}
	if v == "" {
		return "", fmt.Errorf("empty rpmmod in purl qualifiers: %q", p.String())
	}
	name, rest, ok := strings.Cut(v, ":")
	if !ok || rest == "" {
		return "", fmt.Errorf("invalid module name in purl qualifiers: %q", p.String())
	}
	stream, _, _ := strings.Cut(rest, ":")
	if stream == "" {
		return "", fmt.Errorf("invalid module stream in purl qualifiers: %q", p.String())
	}
	return name + ":" + stream, nil
}

// ExtractFixedInVersion deals with 2 pURL types, TypeRPM and TypeOCI
//   - TypeOCI: return the tag qualifier.
//   - TypeRPM: check for an epoch qualifier and prepend it to the purl.Version.
//     If no epoch qualifier, default to 0.
func extractFixedInVersion(p *packageurl.PackageURL) (string, error) {
	switch p.Type {
	case packageurl.TypeOCI:
		t, ok := qualifier(p, "tag")
		if !ok {
			return "", fmt.Errorf("could not find tag qualifier for OCI purl: %q", p.String())
		}
		return t, nil
	case packageurl.TypeRPM:
		if p.Version == "" {
			return "", nil
		}
		epoch := "0"
		if e, ok := qualifier(p, "epoch"); ok {
			epoch = e
		}
		return epoch + ":" + p.Version, nil
	default:
		return "", fmt.Errorf("unexpected purl type: %q", p.Type)
	}
}

// ExtractPackageName deals with 2 pURL types, TypeRPM and TypeOCI
//   - TypeOCI: check if there is Namespace and Name i.e. rhel7/rhel-atomic
//     and return that, if not, check for a repository_url qualifier. If the
//     repository_url exists then use the namespace/name part, if not, use
//     the purl.Name.
//   - TypeRPM: Just return the purl.Name.
func extractPackageName(p *packageurl.PackageURL) (string, error) {
	switch p.Type {
	case packageurl.TypeOCI:
		if p.Namespace != "" {
			return p.Namespace + "/" + p.Name, nil
		}
		// Try finding an image name from the tag qualifier
		ru, ok := qualifier(p, "repository_url")
		if !ok {
			return p.Name, nil
		}
		_, image, found := strings.Cut(ru, "/")
		if !found {
			return "", fmt.Errorf("invalid repository_url for OCI purl: %q", p.String())
		}
		return image, nil
	case packageurl.TypeRPM:
		return p.Name, nil
	default:
		return "", fmt.Errorf("unexpected purl type: %q", p.Type)
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
func checkPURL(p *packageurl.PackageURL) bool {
	if ok := acceptedTypes[p.Type]; !ok {
		return false
	}
	if strings.HasPrefix(p.Name, "kernel") {
		// We don't want to ingest kernel advisories as
		// containers have no say in the kernel.
		return false
	}
	if p.Type == packageurl.TypeRPM && p.Namespace != "redhat" {
		// Not Red Hat rpm content.
		return false
	}
	return true
}

func extractArch(p *packageurl.PackageURL) string {
	arch, _ := qualifier(p, "arch")
	switch arch {
	case "amd64", "x86_64":
		return "amd64|x86_64"
	default:
		return arch
	}
}
