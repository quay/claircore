package acceptance

import "github.com/quay/claircore/toolkit/fixtures"

// Compare checks auditor results against expected results from a fixture.
//
// The comparison logic:
//   - StatusAffected: MUST appear in results as affected. Missing or wrong status is failure.
//   - StatusNotAffected: MUST appear in results as not-affected. Missing or wrong status is failure.
//   - StatusAbsent: MUST NOT appear in results. If present, it's a failure.
//   - Results not in expected are Extras (reported but not a failure).
func Compare(expected []fixtures.ManifestRecord, actual []Result) *Comparison {
	cmp := &Comparison{}

	// Build lookup map: (trackingID, productID) -> expected record
	type key struct{ tid, pid string }
	expectMap := make(map[key]fixtures.ManifestRecord, len(expected))
	for _, e := range expected {
		expectMap[key{e.ID, e.Product}] = e
	}

	seen := make(map[key]bool, len(actual))

	for _, r := range actual {
		k := key{r.TrackingID, r.ProductID}
		seen[k] = true

		exp, ok := expectMap[k]
		if !ok {
			// Found something not in expected.
			cmp.Extras = append(cmp.Extras, r)
			continue
		}

		switch {
		case exp.Status == fixtures.StatusAbsent:
			// Expected NOT to be in results, but it is - failure.
			cmp.Mismatches = append(cmp.Mismatches, Mismatch{
				TrackingID: r.TrackingID,
				ProductID:  r.ProductID,
				Expected:   exp.Status,
				Actual:     r.Status,
			})
		case exp.Status == r.Status:
			cmp.Matches = append(cmp.Matches, Match{
				TrackingID: r.TrackingID,
				ProductID:  r.ProductID,
				Status:     r.Status,
			})
		default:
			cmp.Mismatches = append(cmp.Mismatches, Mismatch{
				TrackingID: r.TrackingID,
				ProductID:  r.ProductID,
				Expected:   exp.Status,
				Actual:     r.Status,
			})
		}
	}

	// Check for missing expected results.
	for _, e := range expected {
		k := key{e.ID, e.Product}
		if seen[k] {
			continue
		}
		switch e.Status {
		case fixtures.StatusAbsent:
			// Expected absent and it IS absent - success (implicit match).
			cmp.Matches = append(cmp.Matches, Match{
				TrackingID: e.ID,
				ProductID:  e.Product,
				Status:     e.Status,
			})
		default:
			// StatusAffected or StatusNotAffected expected but missing - failure.
			cmp.Misses = append(cmp.Misses, e)
		}
	}

	return cmp
}
