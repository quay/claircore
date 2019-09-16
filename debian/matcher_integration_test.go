// +build integration

package debian

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/internal/vulnscanner"
	vulnstore "github.com/quay/claircore/internal/vulnstore/postgres"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/stretchr/testify/assert"
)

// Test_Matcher_Integration confirms packages are matched
// with vulnerabilities correctly. the returned
// store from postgres.NewTestStore must have Ubuntu
// CVE data
func Test_Matcher_Integration(t *testing.T) {
	db, store, teardown := vulnstore.NewTestStore(t)
	defer teardown()

	m := &Matcher{}

	// seed the test vulnstore with CVE data
	deb := NewUpdater(Buster)

	up := updater.New(&updater.Opts{
		Name:    "test-debian-buster",
		Updater: deb,
		Store:   store,
		// set high, we will call update manually
		Interval: 20 * time.Minute,
		Lock:     distlock.NewLock(db, 2*time.Second),
	})
	// force update
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	up.Update(ctx)

	path := filepath.Join("testdata", "scanreport-buster-jackson-databind.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var sr claircore.ScanReport
	err = json.NewDecoder(f).Decode(&sr)
	if err != nil {
		t.Fatalf("failed to decode ScanReport: %v", err)
	}

	vs := vulnscanner.New(store, []matcher.Matcher{m})
	vr, err := vs.Scan(context.Background(), &sr)
	assert.NoError(t, err)

	_, err = json.Marshal(&vr)
	if err != nil {
		t.Fatalf("failed to marshal VR: %v", err)
	}
}
