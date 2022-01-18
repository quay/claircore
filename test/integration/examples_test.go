package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/quay/claircore/test/integration"
)

func ExampleDBSetup() {
	var m *testing.M // This should come from TestMain's argument.
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func ExampleSkip() {
	var t *testing.T // This should come from the test function's argument.
	t.Parallel()
	integration.Skip(t)
	t.Log("OK") // Do some test that needs external setup.
}

func ExampleNeedDB() {
	var t *testing.T // This should come from the test function's argument.
	integration.NeedDB(t)

	ctx := context.Background()
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx, t)

	t.Log("OK") // Do some test that needs a database.
}
