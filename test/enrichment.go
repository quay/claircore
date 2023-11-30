package test

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/quay/claircore/libvuln/driver"
)

// GenEnrichments creates an array of enrichment records, with no meaningful
// content.
func GenEnrichments(n int) []driver.EnrichmentRecord {
	var rs []driver.EnrichmentRecord
	for i := 0; i < n; i++ {
		t := strconv.Itoa(i)
		e := fmt.Sprintf(`{"%[1]d":{"id":%[1]d}}`, i)
		rs = append(rs, driver.EnrichmentRecord{
			Tags:       []string{t},
			Enrichment: json.RawMessage(e),
		})
	}
	return rs
}
