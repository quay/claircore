package kev

// Entry is the enricher's output type.
type Entry struct {
	CVE                        string `json:"cve"`
	VulnerabilityName          string `json:"vulnerability_name"`
	CatalogVersion             string `json:"catalog_version"`
	DateAdded                  string `json:"date_added"`
	ShortDescription           string `json:"short_description"`
	RequiredAction             string `json:"required_action"`
	DueDate                    string `json:"due_date"`
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use"`
}

// Root represents the root structure of the body returned by
// https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json.
type Root struct {
	Title           string           `json:"title,omitempty"`
	CatalogVersion  string           `json:"catalogVersion"`
	DateReleased    string           `json:"dateReleased"`
	Count           int              `json:"count"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a vulnerability based on the CISA KEV schema:
// https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json.
type Vulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string   `json:"notes,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
}
