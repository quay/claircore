package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/quay/claircore/pkg/inspector"
	"github.com/quay/claircore/ubuntu"
	"golang.org/x/sync/errgroup"
)

const (
	testDataDir = "testdata"
)

// define an array of Fixture pointers
// we will concurrently populate the rest of these
// structs and serialize them to disk
var fixtures = []*Fixture{
	// supported ubuntu releases
	{
		Image:   "ubuntu:14.04",
		Updater: string(ubuntu.Trusty),
		updater: ubuntu.NewUpdater(ubuntu.Trusty),
	},
	{
		Image:   "ubuntu:16.04",
		Updater: string(ubuntu.Xenial),
		updater: ubuntu.NewUpdater(ubuntu.Xenial),
	},
	{
		Image:   "ubuntu:18.04",
		Updater: string(ubuntu.Bionic),
		updater: ubuntu.NewUpdater(ubuntu.Bionic),
	},
	{
		Image:   "ubuntu:19.10",
		Updater: string(ubuntu.Eoan),
		updater: ubuntu.NewUpdater(ubuntu.Eoan),
	},
	{
		Image:   "ubuntu:20.04",
		Updater: string(ubuntu.Focal),
		updater: ubuntu.NewUpdater(ubuntu.Focal),
	},
}

func main() {
	ctx := context.Background()

	// create all the depedencies necessary to create
	// fixtures
	deps, err := initialize(ctx)
	if err != nil {
		log.Fatalf("could not initialize: %v", err)
	}

	// concurrently create fixtures
	groupSize := 4
	for i := 0; i < len(fixtures); i += groupSize {
		n := i + groupSize
		if n > len(fixtures) {
			n = len(fixtures)
		}

		g, gctx := errgroup.WithContext(ctx)
		for j := i; j < n; j++ {
			log.Printf("generating fixtures for %v", fixtures[j].updater.Name())
			g.Go(createFixtures(gctx, deps, fixtures[j]))
		}
		g.Wait()
	}

	// write fixtures.json to use as test table in acceptance test
	log.Printf("writing out fixtures to fixtures.json")

	fixF := filepath.Join(testDataDir, "fixtures.json")
	fixFD, err := os.OpenFile(fixF, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("failed to create fixtures file: %v", err)
	}

	err = json.NewEncoder(fixFD).Encode(fixtures)
	if err != nil {
		log.Fatalf("failed to serialize fixtures to file: %v", err)
	}

	log.Fatalf("successfully created acceptance test fixtures")
}

// createFixtures constructs a functi n suitable for
// an errgroup that creates acceptance test fixtures.
func createFixtures(ctx context.Context, deps deps, fix *Fixture) func() error {
	return func() error {
		w, fp, err := fix.updater.Fetch(ctx, "")
		if w != nil {
			defer w.Close()
		}
		if err != nil {
			return err
		}

		// sec-db fixture filename format {UpdaterName-TimeStamp-DatabaseFingerprint}
		dbF := fix.updater.Name() + "-" + string(fp)
		dbF = filepath.Join(testDataDir, dbF)
		dbFD, err := os.OpenFile(dbF, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if dbFD != nil {
			defer dbFD.Close()
		}
		if err != nil {
			return err
		}
		fix.SecDB = dbF

		// tee off reads during parse to our fixture file
		tee := io.TeeReader(w, dbFD)
		vulns, err := fix.updater.Parse(ctx, ioutil.NopCloser(tee))
		if err != nil {
			return err
		}

		// write vulns to vulnstore
		deps.vulnStore.UpdateVulnerabilities(
			ctx,
			fix.updater.Name(),
			fp,
			vulns,
		)

		// create manifest
		manifest, err := inspector.Inspect(ctx, fix.Image)
		if err != nil {
			return err
		}

		// create IndexReport and time it
		start := time.Now()
		ir, err := deps.libI.Index(ctx, manifest)
		if err != nil {
			return err
		}
		if ir.Err != "" {
			return fmt.Errorf("err: %s", ir.Err)
		}
		fix.IRDuration = time.Now().Sub(start)

		irF := url.QueryEscape(fix.Image + "-index_report.json")
		irF = filepath.Join(testDataDir, irF)
		irFD, err := os.OpenFile(irF, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if irFD != nil {
			defer irFD.Close()
		}
		if err != nil {
			return err
		}
		err = json.NewEncoder(irFD).Encode(&ir)
		if err != nil {
			return err
		}
		fix.IR = irF

		// create VulnReport and time it
		start = time.Now()
		vr, err := deps.libV.Scan(ctx, ir)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}
		fix.VRDuration = time.Now().Sub(start)

		vrF := url.QueryEscape(fix.Image + "-vuln_report.json")
		vrF = filepath.Join(testDataDir, vrF)
		vrFD, err := os.OpenFile(vrF, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if vrFD != nil {
			defer vrFD.Close()
		}
		if err != nil {
			return err
		}
		err = json.NewEncoder(vrFD).Encode(&vr)
		if err != nil {
			return err
		}
		fix.VR = vrF

		return nil
	}
}
