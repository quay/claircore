package cvss

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

type vulnFeed struct {
	Total int             `json:"totalResults"`
	Vulns json.RawMessage `json:"vulnerabilities"`
}

// This is an envelope type so we can get at the cvssv3 objects way in there.
type vuln struct {
	CVE struct {
		ID         string `json:"id"`
		VulnStatus string `json:"vulnStatus"`
		Metrics    struct {
			V30 []struct {
				Type string          `json:"type"`
				CVSS json.RawMessage `json:"cvssData"`
			} `json:"cvssMetricV30"`
			V31 []struct {
				Type string          `json:"type"`
				CVSS json.RawMessage `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
	} `json:"cve"`
}

type itemFeed struct {
	year  int
	items []vuln
}

func newItemFeed(year int, r io.Reader) (*itemFeed, error) {
	var feed vulnFeed
	err := json.NewDecoder(r).Decode(&feed)
	if err != nil {
		return nil, err
	}
	items := make([]vuln, 0, feed.Total)
	err = json.Unmarshal(feed.Vulns, &items)
	if err != nil {
		return nil, err
	}
	return &itemFeed{
		year:  year,
		items: items,
	}, nil
}

// Enricher data is written as a series of objects instead of a slice (JSON
// array) of objects to avoid needing to construct the slice and buffer the
// entire serialization in memory.

func (f *itemFeed) WriteCVSS(ctx context.Context, w io.Writer) error {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/cvss/itemFeed/WriteCVSS")
	// Use records directly because our parse step doesn't actually parse
	// anything -- the Fetch step rips out the relevant JSON.
	var skip, wrote uint
	enc := json.NewEncoder(w)
	for _, v := range f.items {
		if strings.EqualFold(v.CVE.VulnStatus, "Rejected") {
			// Ignore rejected vulnerabilities.
			skip++
			continue
		}
		var enrichment json.RawMessage
		for _, cvss := range v.CVE.Metrics.V30 {
			if cvss.Type != "Primary" {
				continue
			}
			enrichment = cvss.CVSS
			break
		}
		// Prefer CVSS 3.1 over 3.0.
		for _, cvss := range v.CVE.Metrics.V31 {
			if cvss.Type != "Primary" {
				continue
			}
			enrichment = cvss.CVSS
			break
		}
		if enrichment == nil {
			// Did not find a CVSS 3.x from the primary source.
			skip++
			continue
		}
		r := driver.EnrichmentRecord{
			Tags:       []string{v.CVE.ID},
			Enrichment: enrichment,
		}
		if err := enc.Encode(&r); err != nil {
			return err
		}
		wrote++
	}
	zlog.Debug(ctx).
		Int("year", f.year).
		Uint("skip", skip).
		Uint("wrote", wrote).
		Msg("wrote cvss items")
	return nil
}
