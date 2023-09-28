package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

const updater string = "test-updater"

type diffTestCase struct {
	Added, Removed    int
	FirstOp, SecondOp []*claircore.Vulnerability
}

// TestGetUpdateDiff creates two update operations in the test DB and calculates
// their diff. This flow is also tested in TestE2E. However, not all the cases
// are captured there, e.g. if there's no difference between the two operations.
func TestGetUpdateDiff(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	cases := []diffTestCase{
		// second op adds two new vulns
		{
			Added:   2,
			Removed: 0,
			FirstOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "vi",
					},
				},
			},
			SecondOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "vi",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "vim",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "nano",
					},
				},
			},
		},
		// one vuln is the same for first and second op, the other one differs
		{
			Added:   1,
			Removed: 1,
			FirstOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "grep",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "sed",
					},
				},
			},
			SecondOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "grep",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "awk",
					},
				},
			},
		},
		// first op has two more vulns that the second op
		{
			Added:   0,
			Removed: 2,
			FirstOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "python3",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "python3-crypto",
					},
				},
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "python3-urllib3",
					},
				},
			},
			SecondOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "python3",
					},
				},
			},
		},
		// no difference between first and second op
		{
			Added:   0,
			Removed: 0,
			FirstOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "perl",
					},
				},
			},
			SecondOp: []*claircore.Vulnerability{
				{
					Updater: updater,
					Package: &claircore.Package{
						Name: "perl",
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
		name := getTestCaseName(tc)
		prev, err := store.UpdateVulnerabilities(ctx, updater, driver.Fingerprint(uuid.New().String()), tc.FirstOp)
		if err != nil {
			t.Fatalf("failed to perform update for first op: %v", err)
		}
		cur, err := store.UpdateVulnerabilities(ctx, updater, driver.Fingerprint(uuid.New().String()), tc.SecondOp)
		if err != nil {
			t.Fatalf("failed to perform update for second op: %v", err)
		}
		diff, err := store.GetUpdateDiff(ctx, prev, cur)
		if err != nil {
			t.Fatalf("received error getting UpdateDiff: %v", err)
		}

		if l := len(diff.Added); l != tc.Added {
			t.Fatalf("%s: got %d added vulns, want %d", name, l, tc.Added)
		}
		if l := len(diff.Removed); l != tc.Removed {
			t.Fatalf("%s: got %d removed vulns, want %d", name, l, tc.Removed)
		}
	}
}

func getTestCaseName(tc diffTestCase) string {
	return fmt.Sprintf("%d added and %d removed", tc.Added, tc.Removed)
}
