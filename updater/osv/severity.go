// Package osv is an updater for OSV-formatted advisories.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/quay/claircore"
)

// default for now - should look at the aliases, find the HSA and get the CVSS sev from it
func getSeverityFromAlias(alias string) (sev claircore.Severity, err error) {
	return claircore.Unknown, nil
}

// First check the Database opaque object if there is a severity
// If not , check if there is an alias we can use
func extractSeverityFromAdvisory(a advisory) (sev claircore.Severity, err error) {
	sev, err = extractSeverityFromDatabase(a)
	if err == nil {
		return sev, nil
	}

	for _, alias := range a.Aliases {
		if strings.Contains(strings.ToUpper(alias), "GHSA") {
			return getSeverityFromAlias(alias)
		}
	}

	return sev, fmt.Errorf("No Severity found in Database, no aliases pointing to GHSA")
}

// check if severity (lower case) exists in the Database object if so, use it
func extractSeverityFromDatabase(a advisory) (sev claircore.Severity, err error) {
	advisoryDatabase := a.Database
	var databaseJSON map[string]json.RawMessage
	if err := json.Unmarshal([]byte(advisoryDatabase), &databaseJSON); err != nil {
		return sev, fmt.Errorf("No Database")
	}
	lowerDatabaseJSON := make(map[string]json.RawMessage, len(databaseJSON))
	for key, value := range databaseJSON {
		lowerDatabaseJSON[strings.ToLower(key)] = value
	}
	var str string
	if err := json.Unmarshal(databaseJSON["severity"], &str); err != nil {
		return sev, fmt.Errorf("No Severity")
	}

	return fromString(str)
}

// returns claircore.Severity basd on  the severity String
func fromString(s string) (sev claircore.Severity, err error) {

	switch {
	case strings.EqualFold(s, "none"):
		sev = claircore.Negligible
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
		return sev, fmt.Errorf("bogus score: %v", s)
	}
	return sev, nil
}
