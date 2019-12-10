package rhel

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/updater"
	"github.com/quay/claircore/internal/vulnscanner"
	vulnstore "github.com/quay/claircore/internal/vulnstore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	distlock "github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

func TestMatcherIntegration(t *testing.T) {
	integration.Skip(t)
	ctx := context.Background()
	logger := log.TestLogger(t)
	ctx = logger.WithContext(ctx)

	db, store, _, teardown := vulnstore.TestStore(ctx, t)
	defer teardown()

	m := &Matcher{}

	fs, err := filepath.Glob("testdata/*.xml")
	if err != nil {
		t.Error(err)
	}
	us := make([]*updater.Controller, len(fs))
	for i, f := range fs {
		u, err := test.Updater(f)
		if err != nil {
			t.Error(err)
			continue
		}
		us[i] = updater.New(&updater.Opts{
			Name:     fmt.Sprintf("test-%s", filepath.Base(f)),
			Updater:  u,
			Store:    store,
			Interval: -1 * time.Minute,
			Lock:     distlock.NewLock(db, 2*time.Second),
		})
	}

	// force update
	wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(len(us))
	for _, c := range us {
		c := c
		go func() {
			c.Update(wctx)
			wg.Done()
		}()
	}
	wg.Wait()

	f, err := os.Open(filepath.Join("testdata", "rhel-report.json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer f.Close()

	var sr claircore.IndexReport
	if err := json.NewDecoder(f).Decode(&sr); err != nil {
		t.Fatalf("failed to decode IndexReport: %v", err)
	}

	vs := vulnscanner.New(store, []driver.Matcher{m})
	vr, err := vs.Scan(ctx, &sr)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.NewEncoder(ioutil.Discard).Encode(&vr); err != nil {
		t.Fatalf("failed to marshal VR: %v", err)
	}
}
