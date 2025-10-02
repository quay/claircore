package postgres

import (
	"testing"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

type latestVulnTestCase struct {
	TestName          string
	Updater           string
	VulnCount         int
	FirstOp, SecondOp *op
	Records           []*claircore.IndexRecord
}

type op struct {
	vulns        []*claircore.Vulnerability
	deletedVulns []string
}

func TestGetLatestVulnerabilities(t *testing.T) {
	integration.NeedDB(t)
	ctx := test.Logging(t)

	cases := []latestVulnTestCase{
		{
			TestName:  "test initial op vuln still relevant",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "vi",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "vim",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "nano",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "vi",
						Source: &claircore.Package{
							Name:    "vi",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test vuln is overwritten not duped",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "BAD",
					},
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "sed",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "NOT AS BAD AS WE THOUGHT",
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "grep",
						Source: &claircore.Package{
							Name:    "grep",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test multiple vulns from same CVE",
			Updater:   updater,
			VulnCount: 1,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "BAD",
					},
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "sed",
						},
						Severity: "REALLY BAD",
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "grep",
						},
						Severity: "NOT AS BAD AS WE THOUGHT",
					},
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "sed",
						},
						Severity: "FINE",
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "grep",
						Source: &claircore.Package{
							Name:    "grep",
							Version: "v1.0.0",
						},
					},
				},
			},
		},

		{
			TestName:  "test two vulns same package different uo",
			Updater:   updater,
			VulnCount: 2,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-000",
						Package: &claircore.Package{
							Name: "python3",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-123",
						Package: &claircore.Package{
							Name: "python3",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "python3-crypto",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "python3-urllib3",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "python3",
						Source: &claircore.Package{
							Name:    "python3",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
		{
			TestName:  "test deleting vuln",
			Updater:   updater,
			VulnCount: 0,
			FirstOp: &op{
				deletedVulns: []string{},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-000",
						Package: &claircore.Package{
							Name: "jq",
						},
					},
				},
			},
			SecondOp: &op{
				deletedVulns: []string{"CVE-000"},
				vulns: []*claircore.Vulnerability{
					{
						Updater: updater,
						Name:    "CVE-456",
						Package: &claircore.Package{
							Name: "jq-libs",
						},
					},
					{
						Updater: updater,
						Name:    "CVE-789",
						Package: &claircore.Package{
							Name: "jq-docs",
						},
					},
				},
			},
			Records: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name: "jq",
						Source: &claircore.Package{
							Name:    "jq",
							Version: "v1.0.0",
						},
					},
				},
			},
		},
	}

	// prepare DB
	pool := pgtest.TestMatcherDB(ctx, t)
	store := NewMatcherStore(pool)

	// run test cases
	for _, tc := range cases {
		t.Run(tc.TestName, func(t *testing.T) {
			ctx := test.Logging(t, ctx)
			_, err := store.DeltaUpdateVulnerabilities(ctx, tc.Updater, driver.Fingerprint(uuid.New().String()), tc.FirstOp.vulns, tc.FirstOp.deletedVulns)
			if err != nil {
				t.Fatalf("failed to perform update for first op: %v", err)
			}
			_, err = store.DeltaUpdateVulnerabilities(ctx, tc.Updater, driver.Fingerprint(uuid.New().String()), tc.SecondOp.vulns, tc.SecondOp.deletedVulns)
			if err != nil {
				t.Fatalf("failed to perform update for second op: %v", err)
			}

			res, err := store.Get(ctx, tc.Records, datastore.GetOpts{})
			if err != nil {
				t.Fatalf("failed to get vulns: %v", err)
			}
			ct := 0
			for _, vs := range res {
				ct = ct + len(vs)
			}

			if ct != tc.VulnCount {
				t.Fatalf("got %d vulns, want %d", ct, tc.VulnCount)
			}
		})
	}
}
