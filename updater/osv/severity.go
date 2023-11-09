// Package osv is an updater for OSV-formatted advisories.
package osv

import (
	"encoding/json"
	"strings"

	"github.com/quay/claircore"
)

// check if severity (lower case) exists in the Database object if so, use it
func extractSeverityFromDatabase(defaultSev claircore.Severity, a advisory) (sev claircore.Severity) {
	advisoryDatabase := a.Database
	var databaseJSON map[string]json.RawMessage
	if err := json.Unmarshal([]byte(advisoryDatabase), &databaseJSON); err == nil {
		lowerDatabaseJSON := make(map[string]json.RawMessage, len(databaseJSON))
		for key, value := range databaseJSON {
			lowerDatabaseJSON[strings.ToLower(key)] = value
		}
		var severityString string
		if err := json.Unmarshal(databaseJSON["severity"], &severityString); err == nil {
			return severityFromString(defaultSev, severityString)
		}
	}
	return defaultSev
}

// returns claircore.Severity based on the String or return the default Severity
func severityFromString(defaultSev claircore.Severity, s string) (sev claircore.Severity) {
	switch {
	case strings.EqualFold(s, "none"):
		sev = claircore.Unknown
	case strings.EqualFold(s, "negligible"):
		sev = claircore.Negligible
	case strings.EqualFold(s, "low"):
		sev = claircore.Low
	case strings.EqualFold(s, "moderate"):
		sev = claircore.Medium
	case strings.EqualFold(s, "medium"):
		sev = claircore.Medium
	case strings.EqualFold(s, "high"):
		sev = claircore.High
	case strings.EqualFold(s, "critical"):
		sev = claircore.Critical
	default:
		sev = defaultSev
	}
	return sev
}
