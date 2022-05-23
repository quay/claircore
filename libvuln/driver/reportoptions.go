package driver

// ReportOptions are used to manipulate what information is included in the
// VulnerabilityReport. They are passed at time of matching so can be dynamically
// set from information on a http request or CLI flag etc.
type ReportOptions struct {
	// IncludeEnrichment flag is used to include CVSS enrichment data in the final
	// VulnerabilityReport.
	IncludeEnrichment bool
}
