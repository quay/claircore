package acceptance

import (
	"flag"
	"os"
	"testing"

	"github.com/quay/claircore/test/integration"
)

// FixturesRepo is the OCI repository containing acceptance test fixtures.
// Each image in this repo has VEX documents and expected results attached
// via OCI referrers.
var FixturesRepo = "quay.io/projectquay/clair-fixtures"

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()

	flag.StringVar(&FixturesRepo, "fixtures-repo", FixturesRepo, "the OCI repository to check for fixtures")
	flag.Parse()

	c = m.Run()
}
