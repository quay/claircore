package debian

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

func init() {
	pkgVersionRegex = regexp.MustCompile(PkgNameVersion)
}

const (
	OVALTemplate   = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
	PkgNameVersion = `([^\s]+) DPKG is earlier than (.+)`
)

var pkgVersionRegex *regexp.Regexp

// pkgInfo is a helper struct when parsing Criterias
type pkgInfo struct {
	name    string
	version string
}

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as an Updater.
type Updater struct {
	// the url to fetch the OVAL db from
	url string
	// the release name as described by os-release "VERSION_CODENAME"
	release Release
	c       *http.Client
}

func NewUpdater(release Release) *Updater {
	url := fmt.Sprintf(OVALTemplate, release)

	return &Updater{
		url:     url,
		release: release,
		c:       &http.Client{},
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf(`debian-%s-updater`, string(u.release))
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "debian/Updater.Fetch").
		Str("release", string(u.release)).
		Str("database", u.url).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("fetching latest oval database")
	var rc io.ReadCloser
	var hash string
	var err error

	rc, hash, err = u.fetch(ctx)

	log.Info().Msg("fetched latest oval database successfully")
	return rc, driver.Fingerprint(hash), err
}

func (u *Updater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "debian/Updater.Parse").
		Str("release", string(u.release)).
		Str("database", u.url).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("parsing oval database")
	defer contents.Close()

	log.Debug().Msg("decoding xml database")
	ovalRoot := oval.Root{}
	err := xml.NewDecoder(contents).Decode(&ovalRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to decode OVAL xml contents: %v", err)
	}
	log.Debug().
		Int("count", len(ovalRoot.Definitions.Definitions)).
		Msg("finished decoding xml database")

	result := []*claircore.Vulnerability{}
	for _, def := range ovalRoot.Definitions.Definitions {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// not a vulnerability
		if def.Class != "vulnerability" {
			continue
		}

		// no CVE identifier
		if def.Title == "" {
			continue
		}

		// walk Criterias to get package info.
		// typically a definition only contains a single package (unlike ubuntu), however we can be defensive and walk the entire recurisve structure if this changes in the future.
		pkgInfos := walkCri(def.Criteria, []pkgInfo{})

		for _, pkgInfo := range pkgInfos {
			vuln := u.classifyVuln(pkgInfo, def)
			result = append(result, vuln)
		}
	}

	return result, nil
}

func (u *Updater) classifyVuln(pkgInfo pkgInfo, def oval.Definition) *claircore.Vulnerability {
	ccPkg := &claircore.Package{
		Name: pkgInfo.name,
	}

	vuln := &claircore.Vulnerability{
		Name:           def.Title,
		Description:    def.Description,
		Links:          ovalutil.Links(def),
		Severity:       "Unknown", // oval db doesnt provide
		Package:        ccPkg,
		FixedInVersion: pkgInfo.version,
		Dist:           releaseToDist(u.release),
	}

	return vuln
}

func walkCri(root oval.Criteria, pkgs []pkgInfo) []pkgInfo {
	for _, crio := range root.Criterions {
		if matches := pkgVersionRegex.FindStringSubmatch(crio.Comment); matches != nil {
			pkgs = append(pkgs, pkgInfo{matches[1], matches[2]})
		}
	}

	if len(root.Criterias) == 0 {
		return pkgs
	}

	// recurse till no more Criterias
	for _, cria := range root.Criterias {
		pkgs = walkCri(cria, pkgs)
	}

	return pkgs
}
