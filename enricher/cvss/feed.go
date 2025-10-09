package cvss

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"

	"github.com/quay/claircore/libvuln/driver"
)

type vulnFeed struct {
	Total int             `json:"totalResults"`
	Vulns json.RawMessage `json:"vulnerabilities"`
}

type metric struct {
	Type string          `json:"type"`
	CVSS json.RawMessage `json:"cvssData"`
}

type vuln struct {
	CVE struct {
		ID         string `json:"id"`
		VulnStatus string `json:"vulnStatus"`
		Metrics    struct {
			V30 []metric `json:"cvssMetricV30"`
			V31 []metric `json:"cvssMetricV31"`
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
		// Prefer CVSS 3.1 over 3.0.
		seq := func(yield func(metric) bool) {
			for _, m := range v.CVE.Metrics.V31 {
				if !yield(m) {
					return
				}
			}
			for _, m := range v.CVE.Metrics.V30 {
				if !yield(m) {
					return
				}
			}
		}
		var enrichment json.RawMessage
		for m := range seq {
			if m.Type == "Primary" {
				enrichment = m.CVSS
				break
			}
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
	slog.DebugContext(ctx, "wrote cvss items",
		"year", f.year,
		"skip", skip,
		"wrote", wrote)
	return nil
}
