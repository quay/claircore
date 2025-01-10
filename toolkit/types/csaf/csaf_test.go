package csaf

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var testBattery = []struct {
	path                 string
	product              *Product
	relationship         *Relationship
	remediationProductID string
	remediation          *RemediationData
	scoreProductID       string
	score                *Score
	severity             AggregateSeverity
	prodIdentifier       *Product
	threatProductID      string
	threatData           *ThreatData
}{
	{
		path: "testdata/cve-2021-0084.json",
		product: &Product{
			Name: "Red Hat Enterprise Linux 9",
			ID:   "red_hat_enterprise_linux_9",
			IdentificationHelper: map[string]string{
				"cpe": "cpe:/o:redhat:enterprise_linux:9",
			},
		},
		relationship: &Relationship{
			Category:   "default_component_of",
			ProductRef: "kernel",
			FullProductName: Product{
				Name: "kernel as a component of Red Hat Enterprise Linux 9",
				ID:   "red_hat_enterprise_linux_9:kernel",
			},
			RelatesToProductRef: "red_hat_enterprise_linux_9",
		},
		remediation: nil, // no remediation data in this file
		score:       nil, // no score data in this file
		severity: AggregateSeverity{
			Namespace: "https://access.redhat.com/security/updates/classification/",
			Text:      "important",
		},
		prodIdentifier: &Product{
			Name: "Red Hat Enterprise Linux 7",
			ID:   "red_hat_enterprise_linux_7",
			IdentificationHelper: map[string]string{
				"cpe": "cpe:/o:redhat:enterprise_linux:7",
			},
		},
	},
	{
		path: "testdata/rhsa-2022-0011.json",
		product: &Product{
			Name: "Red Hat Enterprise Linux Server AUS (v. 7.6)",
			ID:   "7Server-7.6.AUS",
			IdentificationHelper: map[string]string{
				"cpe": "cpe:/o:redhat:rhel_aus:7.6::server",
			},
		},
		relationship: &Relationship{
			Category:   "default_component_of",
			ProductRef: "telnet-server-1:0.17-65.el7_6.x86_64",
			FullProductName: Product{
				Name: "telnet-server-1:0.17-65.el7_6.x86_64 as a component of Red Hat Enterprise Linux Server TUS (v. 7.6)",
				ID:   "7Server-7.6.TUS:telnet-server-1:0.17-65.el7_6.x86_64",
			},
			RelatesToProductRef: "7Server-7.6.TUS",
		},
		remediationProductID: "7Server-7.6.AUS:telnet-1:0.17-65.el7_6.src",
		remediation: &RemediationData{
			Category: "vendor_fix",
			Details:  "For details on how to apply this update, which includes the changes described in this advisory, refer to:\n\nhttps://access.redhat.com/articles/11258",
			URL:      "https://access.redhat.com/errata/RHSA-2022:0011",
		},
		score: nil, // no score for RHSAs
		severity: AggregateSeverity{
			Namespace: "https://access.redhat.com/security/updates/classification/",
			Text:      "Important",
		},
		prodIdentifier: &Product{
			Name: "Red Hat Enterprise Linux Server E4S (v. 7.6)",
			ID:   "7Server-7.6.E4S",
			IdentificationHelper: map[string]string{
				"cpe": "cpe:/o:redhat:rhel_e4s:7.6::server",
			},
		},
	},
	{
		path: "testdata/cve-2024-22047.json",
		product: &Product{
			Name: "rubygem-audited",
			ID:   "rubygem-audited",
		},
		relationship: &Relationship{
			Category:   "default_component_of",
			ProductRef: "rubygem-audited",
			FullProductName: Product{
				Name: "rubygem-audited as a component of Red Hat Satellite 6",
				ID:   "red_hat_satellite_6:rubygem-audited",
			},
			RelatesToProductRef: "red_hat_satellite_6",
		},
		remediationProductID: "red_hat_satellite_6:rubygem-audited",
		remediation: &RemediationData{
			Category: "none_available",
			Details:  "Affected",
		},
		scoreProductID: "red_hat_satellite_6:rubygem-audited",
		score: &Score{
			CVSSV3: &CVSSV3{
				VectorString: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",
				Version:      "3.1",
				BaseScore:    3.1,
				BaseSeverity: "LOW",
			},
			ProductIDs: []string{"red_hat_satellite_6:rubygem-audited"},
		},
		severity: AggregateSeverity{
			Namespace: "https://access.redhat.com/security/updates/classification/",
			Text:      "low",
		},
		threatProductID: "red_hat_satellite_6:rubygem-audited",
		threatData: &ThreatData{
			Category:   "impact",
			Details:    "Low",
			ProductIDs: []string{"red_hat_satellite_6:rubygem-audited"},
		},
		prodIdentifier: &Product{
			Name: "Red Hat Satellite 6",
			ID:   "red_hat_satellite_6",
			IdentificationHelper: map[string]string{
				"cpe": "cpe:/a:redhat:satellite:6",
			},
		},
	},
	{
		path: "testdata/cve-1999-0001-deleted.json",
	},
}

func TestAll(t *testing.T) {
	for _, tc := range testBattery {
		t.Run(tc.path, func(t *testing.T) {
			f, err := os.Open(tc.path)
			if err != nil {
				t.Fatalf("failed to open test data: %v", err)
			}
			defer f.Close()
			c, err := Parse(f)
			if err != nil {
				t.Fatalf("failed to parse CSAF JSON: %v", err)
			}
			if c.Document.Tracking.Status == "deleted" {
				t.Log("advisory deleted", c.Document.Tracking.ID)
				return
			}
			if !cmp.Equal(tc.severity, c.Document.AggregateSeverity) {
				t.Error(cmp.Diff(tc.severity, c.Document.AggregateSeverity))
			}
			if got := c.ProductTree.FindProductByID(tc.product.ID); !cmp.Equal(tc.product, got) {
				t.Error(cmp.Diff(tc.product, got))
			}
			if got := c.FindRelationship(tc.relationship.FullProductName.ID, tc.relationship.Category); !cmp.Equal(tc.relationship, got) {
				t.Error(cmp.Diff(tc.relationship, got))
			}
			if got := c.FindRemediation(tc.remediationProductID); !cmp.Equal(tc.remediation, got, cmpopts.IgnoreFields(RemediationData{}, "ProductIDs")) {
				t.Error(cmp.Diff(tc.remediation, got))
			}
			if got := c.FindScore(tc.scoreProductID); !cmp.Equal(tc.score, got) {
				t.Error(cmp.Diff(tc.score, got))
			}
			if got := c.FindThreat(tc.threatProductID, "impact"); !cmp.Equal(tc.threatData, got) {
				t.Error(cmp.Diff(tc.threatData, got))
			}
			if got := c.ProductTree.Branches[0].FindProductIdentifier("cpe", tc.prodIdentifier.IdentificationHelper["cpe"]); !cmp.Equal(tc.prodIdentifier, got) {
				t.Error(cmp.Diff(tc.prodIdentifier, got))
			}
		})
	}
}
