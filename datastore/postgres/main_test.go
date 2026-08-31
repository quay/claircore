package postgres

import (
	"testing"

	"github.com/quay/claircore/test"
)

func TestMain(m *testing.M) {
	test.Main(m, test.DBSetup)
}
