package debian

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

const linkPrefix = `https://security-tracker.debian.org/tracker/`

// JSONData maps source package -> related vulnerabilities
type JSONData map[string]Vulnerabilities

// Vulnerabilities maps vulnerability ID (CVE) -> related data
type Vulnerabilities map[string]*Vulnerability

// Vulnerability is data related to a vulnerability
type Vulnerability struct {
	Description string                 `json:"description"`
	Releases    map[string]ReleaseData `json:"releases"`
}

// ReleaseData is data related to releases related to a vulnerability
type ReleaseData struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// Parse implements [driver.Parser].
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "debian/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()

	var vulnsJSON JSONData
	err := json.NewDecoder(r).Decode(&vulnsJSON)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON vulnerability feed: %w", err)
	}

	var vs []*claircore.Vulnerability
	for src, vulns := range vulnsJSON {
		for id, vulnData := range vulns {
			for release, releaseData := range vulnData.Releases {
				d, err := getDist(release)
				if err != nil {
					// Don't log here to ensure logs aren't blown up with
					// entries referring to sid or an unreleased Debian version.
					continue
				}

				v := claircore.Vulnerability{
					Updater:            u.Name(),
					Name:               id,
					Description:        vulnData.Description,
					Links:              linkPrefix + id,
					Severity:           releaseData.Urgency,
					NormalizedSeverity: normalizeSeverity(releaseData.Urgency),
					Dist:               d,
					FixedInVersion:     releaseData.FixedVersion,
					Package: &claircore.Package{
						Name: src,
						Kind: claircore.SOURCE,
					},
				}
				vs = append(vs, &v)

				for _, bin := range u.sm.Get(d.VersionCodeName, src) {
					// Shallow copy.
					vuln := v
					vuln.Package = &claircore.Package{
						Name: bin,
						Kind: claircore.BINARY,
					}

					vs = append(vs, &vuln)
				}
			}
		}
	}

	return vs, nil
}
