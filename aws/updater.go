package aws

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"

	"github.com/quay/alas"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as a claircore.Updater
type Updater struct {
	release Release
}

func NewUpdater(release Release) (*Updater, error) {
	return &Updater{
		release: release,
	}, nil
}

func (u *Updater) Name() string {
	panic("not implemented")
}

func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	client, err := NewClient(u.release)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create client: %v", err)
	}

	repoMD, err := client.RepoMD()
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve repo metadata: %v", err)
	}
	log.Printf("%v", repoMD)

	updatesRepoMD, err := repoMD.Repo(alas.UpdateInfo, "")
	if err != nil {
		return nil, "", fmt.Errorf("updates repo metadata could not be retrieved: %v", err)
	}

	resp, err := client.Updates()
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve update info: %v", err)
	}

	gzip, err := gzip.NewReader(resp.Body)
	if err != nil {
		// log.Printf("got here!!!!!!!!!")
		return nil, "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	rc := ioutil.NopCloser(gzip)

	return rc, updatesRepoMD.Checksum.Sum, nil
}

func (u *Updater) Parse(contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	var updates alas.Updates
	err := xml.NewDecoder(contents).Decode(&updates)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updates xml: %v", err)
	}

	vulns := []*claircore.Vulnerability{}
	for _, update := range updates.Updates {
		partial := &claircore.Vulnerability{
			Updater:     u.Name(),
			Name:        update.ID,
			Description: update.Description,
			Links:       refsToLinks(update),
			Severity:    update.Severity,
		}
		vulns = append(vulns, u.unpack(partial, update.Packages)...)
		log.Printf("%v", vulns)
	}

	return vulns, nil
}

// unpack takes the partially populated vulnerability and creates a fully populated vulnerability for each
// provided alas.Package
func (u *Updater) unpack(partial *claircore.Vulnerability, packages []alas.Package) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}
	for _, alasPKG := range packages {
		// make copy
		v := *partial

		v.Package = &claircore.Package{
			Name: alasPKG.Name,
			Kind: "binary",
			Dist: &claircore.Distribution{
				VersionCodeName: string(ReleaseToRepo[u.release]),
			},
		}
		v.FixedInVersion = alasPKG.Version

		out = append(out, &v)
	}

	return out
}

// refsToLinks takes an alas.Update and creates a string with all the href links
func refsToLinks(u alas.Update) string {
	out := []string{}
	for _, ref := range u.References {
		out = append(out, ref.Href)
	}

	return strings.Join(out, " ")
}
