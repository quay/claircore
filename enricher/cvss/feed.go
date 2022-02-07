package cvss

import (
	"context"
	"encoding/json"
	"io"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

type cveFeed struct {
	Count int             `json:"CVE_data_numberOfCVEs,string"`
	Items json.RawMessage `json:"CVE_Items"`
}

// This is an envelope type so we can get at the cvssv3 object way in there.
type cve struct {
	CVE struct {
		Meta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
	} `json:"cve"`
	Impact struct {
		V3 struct {
			CVSS json.RawMessage `json:"cvssV3"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
}

type itemFeed struct {
	year  int
	items []cve
}

func newItemFeed(year int, r io.Reader) (*itemFeed, error) {
	var feed cveFeed
	err := json.NewDecoder(r).Decode(&feed)
	if err != nil {
		return nil, err
	}
	items := make([]cve, 0, feed.Count)
	err = json.Unmarshal(feed.Items, &items)
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
	for _, c := range f.items {
		if c.Impact.V3.CVSS == nil {
			skip++
			continue
		}
		r := driver.EnrichmentRecord{
			Tags:       []string{c.CVE.Meta.ID},
			Enrichment: c.Impact.V3.CVSS,
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
