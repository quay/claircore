// Package csaf provides functionality for handling Common Security Advisory Framework Version 2.0
// documents: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
package csaf

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

func Parse(r io.Reader) (*CSAF, error) {
	csafDoc := &CSAF{}
	if err := json.NewDecoder(r).Decode(csafDoc); err != nil {
		return nil, fmt.Errorf("csaf: failed to unmarshal document: %w", err)
	}
	return csafDoc, nil
}

// CSAF is a Common Security Advisory Framework Version 2.0 document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
type CSAF struct {
	// Document contains metadata about the CSAF document itself.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
	Document DocumentMetadata `json:"document"`

	// ProductTree contains information about the product tree (branches only).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#322-product-tree-property
	ProductTree ProductBranch `json:"product_tree"`

	// Vulnerabilities contains information about the vulnerabilities,
	// (i.e. CVEs), associated threats, and product status.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	// Notes holds notes associated with the whole document.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3217-document-property---notes
	Notes []Note `json:"notes"`
}

// DocumentMetadata contains metadata about the CSAF document itself.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
type DocumentMetadata struct {
	Title      string      `json:"title"`
	Tracking   Tracking    `json:"tracking"`
	References []Reference `json:"references"`
	Publisher  Publisher   `json:"publisher"`
}

// Document references holds a list of references associated with the whole document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3219-document-property---references
type Reference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// Tracking contains information used to track the CSAF document through its lifecycle.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32112-document-property---tracking
type Tracking struct {
	ID                 string    `json:"id"`
	CurrentReleaseDate time.Time `json:"current_release_date"`
	InitialReleaseDate time.Time `json:"initial_release_date"`
}

// Publisher provides information on the publishing entity.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3218-document-property---publisher
type Publisher struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details"`
	IssuingAuthority string `json:"issuing_authority"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

// Vulnerability contains information about a CVE and its associated threats.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
type Vulnerability struct {
	// MITRE standard Common Vulnerabilities and Exposures (CVE) tracking number for the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3232-vulnerabilities-property---cve
	CVE string `json:"cve"`

	// List of IDs represents a list of unique labels or tracking IDs for the vulnerability (if such information exists).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
	IDs []TrackingID `json:"ids"`

	// Provide details on the status of the referenced product related to the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3239-vulnerabilities-property---product-status
	ProductStatus map[string][]string `json:"product_status"`

	// Provide details of threats associated with a vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
	Threats []ThreatData `json:"threats"`

	// Provide details of remediations associated with a Vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
	Remediations []RemediationData `json:"remediations"`

	// Machine readable flags for products related to vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
	Flags []Flag `json:"flags"`

	// Vulnerability references holds a list of references associated with this vulnerability item.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32310-vulnerabilities-property---references
	References []Reference `json:"references"`

	ReleaseDate time.Time `json:"release_date"`

	// Notes holds notes associated with the Vulnerability object.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3238-vulnerabilities-property---notes
	Notes []Note `json:"notes"`

	// Scores holds the scores associated with the Vulnerability object.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32313-vulnerabilities-property---scores
	Scores []Score `json:"scores"`
}

// Score contains score information tied to the listed products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32313-vulnerabilities-property---scores

type Score struct {
	// Currently RH only supports V3.
	CVSSV2     *CVSSV2  `json:"cvss_v2"`
	CVSSV3     *CVSSV3  `json:"cvss_v3"`
	CVSSV4     *CVSSV4  `json:"cvss_v4"`
	ProductIDs []string `json:"products"`
}

// CVSSV2 describes CVSSv2.0 specification as defined here:
//   - https://www.first.org/cvss/cvss-v2.0.json
//
// Only the required fields are defined.
type CVSSV2 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// CVSSV3 describes both the CVSSv3.0 and CVSSv3.1 specifications as defined here:
//   - https://www.first.org/cvss/cvss-v3.0.json
//   - https://www.first.org/cvss/cvss-v3.1.json
//
// Only the required fields are defined.
type CVSSV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// CVSSV4 describes CVSSv4.0 specification as defined here:
//   - https://www.first.org/cvss/cvss-v4.0.json
//
// Only the required fields are defined.
type CVSSV4 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// Note describes additional information that is specific to the object in which it's a member.
type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
	Audience string `json:"audience"`
}

// Every ID item with the two mandatory properties System Name (system_name) and Text (text) contains a single unique label or tracking ID for the vulnerability.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
type TrackingID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ThreatData contains information about a threat to a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
type ThreatData struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

// RemediationData contains information about how to remediate a vulnerability for a set of products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
type RemediationData struct {
	Category     string      `json:"category"`
	Date         time.Time   `json:"date"`
	Details      string      `json:"details"`
	Entitlements []string    `json:"entitlements"`
	GroupIDs     []string    `json:"group_ids"`
	ProductIDs   []string    `json:"product_ids"`
	Restart      RestartData `json:"restart_required"`
	URL          string      `json:"url"`
}

// Remediation instructions for restart of affected software.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323127-vulnerabilities-property---remediations---restart-required
type RestartData struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}

// Machine readable flags for products related to the Vulnerability
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
type Flag struct {
	Label      string    `json:"label"`
	Date       time.Time `json:"date"`
	GroupIDs   []string  `json:"group_ids"`
	ProductIDs []string  `json:"product_ids"`
}

// ProductBranch is a recursive struct that contains information about a product and
// its nested products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3221-product-tree-property---branches
type ProductBranch struct {
	Category      string          `json:"category"`
	Name          string          `json:"name"`
	Branches      []ProductBranch `json:"branches"`
	Product       Product         `json:"product"`
	Relationships Relationships   `json:"relationships"`
}

// Relationship establishes a link between two existing full_product_name_t elements, allowing
// the document producer to define a combination of two products that form a new full_product_name entry.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-product-tree-property---relationships
type Relationship struct {
	Category            string  `json:"category"`
	FullProductName     Product `json:"full_product_name"`
	ProductRef          string  `json:"product_reference"`
	RelatesToProductRef string  `json:"relates_to_product_reference"`
}

// Product contains information used to identify a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3124-branches-type---product
type Product struct {
	Name                 string            `json:"name"`
	ID                   string            `json:"product_id"`
	IdentificationHelper map[string]string `json:"product_identification_helper"`
}

// CSAF methods

// FindRemediation returns RemediationData (if it exists) for a given productID otherwise nil.
func (csafDoc *CSAF) FindRemediation(productID string) *RemediationData {
	for _, v := range csafDoc.Vulnerabilities {
		for _, r := range v.Remediations {
			for _, p := range r.ProductIDs {
				if p == productID {
					return &r
				}
			}
		}
	}
	return nil
}

// FindScore returns Score data (if it exists) for a given productID otherwise nil.
func (csafDoc *CSAF) FindScore(productID string) *Score {
	for _, v := range csafDoc.Vulnerabilities {
		for _, s := range v.Scores {
			for _, p := range s.ProductIDs {
				if p == productID {
					return &s
				}
			}
		}
	}
	return nil
}

// FindRelationship returns a Relationship (if it exists) for a given productID-category pair
// otherwise nil.
func (csafDoc *CSAF) FindRelationship(productID, category string) *Relationship {
	return csafDoc.ProductTree.Relationships.FindRelationship(productID, category)
}

// ProductBranch methods

// FindProductIdentifier recursively searches for the first product identifier in the tree
// given the helper value. Helper types are described here:
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3133-full-product-name-type---product-identification-helper
func (branch *ProductBranch) FindProductIdentifier(helperType, helperValue string) *Product {
	if len(branch.Product.IdentificationHelper) != 0 {
		for k := range branch.Product.IdentificationHelper {
			if k != helperType {
				continue
			}
			if branch.Product.IdentificationHelper[k] == helperValue {
				return &branch.Product
			}
		}
	}

	// Recursively search for the first identifier
	for _, b := range branch.Branches {
		if p := b.FindProductIdentifier(helperType, helperValue); p != nil {
			return p
		}
	}

	return nil
}

// FindProductByID recursively searches for the first product identifier in the tree
// given the productID.
func (branch *ProductBranch) FindProductByID(productID string) *Product {
	if branch.Product.ID == productID {
		return &branch.Product
	}

	// Recursively search for the first product id
	for _, b := range branch.Branches {
		if p := b.FindProductByID(productID); p != nil {
			return p
		}
	}

	return nil
}

// Relationships is a slice of Relationship objects
type Relationships []Relationship

// Relationships methods

// FindRelationship looks up a csaf.Relationship from the productID and category strings
// provided.
func (rs *Relationships) FindRelationship(productID, category string) *Relationship {
	for i := range *rs {
		r := &(*rs)[i]
		if r.Category == category && r.FullProductName.ID == productID {
			return r
		}
	}
	return nil
}
