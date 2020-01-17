package aws

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
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
	return fmt.Sprintf("aws-%v-updater", u.release)
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	client, err := NewClient(ctx, u.release)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create client: %v", err)
	}

	tctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	repoMD, err := client.RepoMD(tctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve repo metadata: %v", err)
	}

	updatesRepoMD, err := repoMD.Repo(alas.UpdateInfo, "")
	if err != nil {
		return nil, "", fmt.Errorf("updates repo metadata could not be retrieved: %v", err)
	}

	tctx, cancel = context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	rc, err := client.Updates(tctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve update info: %v", err)
	}

	gzip, err := gzip.NewReader(rc)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	rc = ioutil.NopCloser(gzip)

	return rc, driver.Fingerprint(updatesRepoMD.Checksum.Sum), nil
}

func (u *Updater) Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error) {
	var updates alas.Updates
	err := xml.NewDecoder(contents).Decode(&updates)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updates xml: %v", err)
	}
	dist, err := releaseToDist(u.release)
	if err != nil {
		return nil, fmt.Errorf("failed to classify vulns with distribution: %w", err)
	}

	vulns := []*claircore.Vulnerability{}
	for _, update := range updates.Updates {
		partial := &claircore.Vulnerability{
			Updater:     u.Name(),
			Name:        update.ID,
			Description: update.Description,
			Links:       refsToLinks(update),
			Severity:    update.Severity,
			Dist:        dist,
		}
		vulns = append(vulns, u.unpack(partial, update.Packages)...)
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
		}
		v.FixedInVersion = fmt.Sprintf("%s-%s", alasPKG.Version, alasPKG.Release)

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
