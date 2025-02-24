package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/aws/internal/alas"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as a claircore.Updater
type Updater struct {
	release Release
	c       *http.Client
}

func NewUpdater(release Release) (*Updater, error) {
	return &Updater{
		release: release,
	}, nil
}

func (u *Updater) Name() string {
	return fmt.Sprintf("aws-%v-updater", u.release)
}

func (u *Updater) Configure(ctx context.Context, _ driver.ConfigUnmarshaler, c *http.Client) error {
	// TODO This should be able to configure things, actually.
	u.c = c
	return nil
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "aws/Updater.Fetch")
	client, err := NewClient(ctx, u.c, u.release)
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
	if updatesRepoMD.Checksum.Sum == string(fingerprint) {
		return nil, fingerprint, driver.Unchanged
	}

	tctx, cancel = context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	rc, err := client.Updates(tctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve update info: %v", err)
	}

	return rc, driver.Fingerprint(updatesRepoMD.Checksum.Sum), nil
}

func (u *Updater) Parse(ctx context.Context, contents io.Reader) ([]*claircore.Vulnerability, error) {
	var updates alas.Updates
	dec := xml.NewDecoder(contents)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&updates); err != nil {
		return nil, fmt.Errorf("failed to unmarshal updates xml: %v", err)
	}
	dist := releaseToDist(u.release)

	vulns := []*claircore.Vulnerability{}
	for _, update := range updates.Updates {
		partial := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               update.ID,
			Description:        update.Description,
			Issued:             time.Time(update.Issued.Date),
			Links:              refsToLinks(update),
			Severity:           update.Severity,
			NormalizedSeverity: NormalizeSeverity(update.Severity),
			Dist:               dist,
			ArchOperation:      claircore.OpEquals,
		}
		vulns = append(vulns, u.unpack(partial, update.Packages)...)
	}

	return vulns, nil
}

// unpack takes the partially populated vulnerability and creates a fully populated vulnerability for each
// provided alas.Package
func (u *Updater) unpack(partial *claircore.Vulnerability, packages []alas.Package) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}

	var b strings.Builder
	for _, alasPKG := range packages {
		// make copy
		v := *partial

		v.Package = &claircore.Package{
			Name: alasPKG.Name,
			Kind: claircore.BINARY,
			Arch: alasPKG.Arch,
		}
		v.FixedInVersion = versionString(&b, alasPKG)

		out = append(out, &v)
	}

	b.Reset()
	return out
}

func versionString(b *strings.Builder, p alas.Package) string {
	b.Reset()

	if p.Epoch != "" && p.Epoch != "0" {
		b.WriteString(p.Epoch)
		b.WriteByte(':')
	}
	b.WriteString(p.Version)
	b.WriteByte('-')
	b.WriteString(p.Release)

	return b.String()
}

// refsToLinks takes an alas.Update and creates a string with all the href links
func refsToLinks(u alas.Update) string {
	out := []string{}
	for _, ref := range u.References {
		out = append(out, ref.Href)
	}

	return strings.Join(out, " ")
}
