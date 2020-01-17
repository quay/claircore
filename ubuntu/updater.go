package ubuntu

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

const (
	OVALTemplateBzip = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	OVALTemplate     = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml"
)

var shouldBzipFetch = map[Release]bool{
	Artful:  false,
	Bionic:  true,
	Cosmic:  true,
	Disco:   true,
	Precise: false,
	Trusty:  true,
	Xenial:  true,
}

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as an Updater.
type Updater struct {
	// the url to fetch the OVAL db from
	url string
	// the release name as described by os-releae "VERSION_CODENAME"
	release Release
	c       *http.Client
	// the current vulnerability being parsed. see the Parse() method for more details
	curVuln claircore.Vulnerability
}

func NewUpdater(release Release) *Updater {
	var fetchBzip, ok bool
	if fetchBzip, ok = shouldBzipFetch[release]; !ok {
		return nil
	}

	var url string
	if fetchBzip {
		url = fmt.Sprintf(OVALTemplateBzip, release)
	} else {
		url = fmt.Sprintf(OVALTemplate, release)
	}

	return &Updater{
		url:     url,
		release: release,
		c:       &http.Client{},
	}
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ubuntu/Updater.Fetch").
		Str("database", u.url).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("fetching latest oval database")
	var rc io.ReadCloser
	var hash string
	var err error

	if shouldBzipFetch[u.release] {
		rc, hash, err = u.fetchBzip(ctx)
	} else {
		rc, hash, err = u.fetch(ctx)
	}

	log.Info().Msg("fetched latest oval database successfully")
	return rc, driver.Fingerprint(hash), err
}

func (u *Updater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ubuntu/Updater.Parse").
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
		// resets static curVuln values to empty strings
		u.reset()

		// not a vulnerability
		if def.Class != "vulnerability" {
			continue
		}
		// does not contain a CVE ID
		if len(def.References) == 0 {
			continue
		}

		// each ubuntu CVE contains multiple affected packages. we
		// want to "flatten" these into unique claircore.Vulnerability data structs.
		// lets store the data that remains static for each "flattened" or in other words "unpacked"
		// vulnerability in the current CVE in u.curVuln. we can then copy this struct
		// as we unpack the CVE definition and add the copy with the pkg and dist into to the result array
		u.curVuln.Name = def.References[0].RefID
		u.curVuln.Description = def.Description
		u.curVuln.Links = ovalutil.Links(def)
		u.curVuln.Severity = def.Advisory.Severity

		// now that we have our curVuln setup, unpack each nested package
		// into it's own claircore.Vulnerability struct
		vulns := u.unpack(def.Criteria, []*claircore.Vulnerability{})
		result = append(result, vulns...)
	}
	log.Info().
		Int("count", len(result)).
		Msg("parsed oval database")
	return result, nil
}

func (u *Updater) reset() {
	u.curVuln.Name = ""
	u.curVuln.Description = ""
	u.curVuln.Links = ""
	u.curVuln.Severity = ""
}

// unpack walks the recursive criteria structure and finds all packages. we copy u.curVuln and add the
// unpacked CVE to the result array
func (u *Updater) unpack(cri oval.Criteria, vulns []*claircore.Vulnerability) []*claircore.Vulnerability {
	for _, c := range cri.Criterions {
		if c.Negate {
			continue
		}

		if name, fixVersion, ok := parseNotFixedYet(c.Comment); ok {
			vuln := u.classifyVuln(name, fixVersion)
			vulns = append(vulns, vuln)
		}
		if name, fixVersion, ok := parseNotDecided(c.Comment); ok {
			vuln := u.classifyVuln(name, fixVersion)
			vulns = append(vulns, vuln)
		}
		if name, fixVersion, ok := parseFixed(c.Comment); ok {
			vuln := u.classifyVuln(name, fixVersion)
			vulns = append(vulns, vuln)
		}

		// nop for now
		// <criterion test_ref="oval:com.ubuntu.xenial:tst:10" comment="The vulnerability of the 'brotli' package in xenial is not known (status: 'needs-triage'). It is pending evaluation." />
		// <criterion test_ref="oval:com.ubuntu.bionic:tst:201211480000000" comment="apache2: while related to the CVE in some way, a decision has been made to ignore this issue (note: 'code-not-compiled')." />

	}

	if len(cri.Criterias) == 0 {
		return vulns
	}
	// recurse
	for _, c := range cri.Criterias {
		vulns = u.unpack(c, vulns)
	}

	return vulns
}

// classifyVuln defines the vulnerability's package and distribution data and adds it to the result.
// pay attention here in order to use the same fields as the dpkg package scanner uses when classifying packages
// and distribution information.
func (u *Updater) classifyVuln(name string, fixVersion string) *claircore.Vulnerability {
	pkg := &claircore.Package{
		Name: name,
	}

	// make a copy of u.curVuln. it has the fields representing the curent
	// vulnerability being parsed populated.
	vuln := u.curVuln
	vuln.FixedInVersion = fixVersion
	vuln.Package = pkg
	vuln.Dist = releaseToDist(u.release)
	return &vuln
}

func (u *Updater) Name() string {
	return fmt.Sprintf("ubuntu-%s-updater", u.release)
}
