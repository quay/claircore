package enricher

import "regexp"

// CVERegexp is a slightly more relaxed version of the validation pattern in the NVD
// JSON schema: https://csrc.nist.gov/schema/nvd/feed/1.1/CVE_JSON_4.0_min_1.1.schema.
//
// It allows for "CVE" to be case insensitive and for dashes and underscores
// between the different segments.
var CVERegexp = regexp.MustCompile(`(?i:cve)[-_][0-9]{4}[-_][0-9]{4,}`)
