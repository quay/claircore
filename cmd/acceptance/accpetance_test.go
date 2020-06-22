package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/inspector"
)

const (
	fixturesFName = "fixtures.json"
)

func TestAcceptance(t *testing.T) {
	// load fixtures.json from testdata dir
	fixPath := filepath.Join(testDataDir, fixturesFName)
	f, err := os.OpenFile(fixPath, os.O_RDONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open fixtures.json: %v", err)
	}

	var fixtures = []*Fixture{}
	err = json.NewDecoder(f).Decode(&fixtures)
	if err != nil {
		t.Fatalf("failed to decode fixtures.json: %v", err)
	}

	ctx := context.Background()
	deps, err := initialize(ctx)

	for _, fix := range fixtures {
		t.Run(fix.Image, testAcceptance(ctx, t, deps, fix))
	}
}

// testAcceptance returns a parallel subtest which confirms
// the current codebase produces the same output as the provided fixture
func testAcceptance(ctx context.Context, t *testing.T, deps deps, fix *Fixture) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		// allocate the updater
		err := fix.SetUpdater()
		if err != nil {
			t.Fatalf("%v", err)
		}

		// open secdb, parse contents, write to vulnstore
		dbFD, err := os.Open(fix.SecDB)
		if err != nil {
			t.Fatalf("failed to open fixture secdb: %v", err)
		}
		vulns, err := fix.updater.Parse(ctx, dbFD)
		if err != nil {
			t.Fatalf("failed to parse fixture secdb: %v", err)
		}
		_, err = deps.vulnStore.UpdateVulnerabilities(ctx, fix.updater.Name(), "", vulns)
		if err != nil {
			t.Fatalf("failed to store vulns: %v", err)
		}

		// create manifest
		manifest, err := inspector.Inspect(ctx, fix.Image)
		if err != nil {
			t.Fatalf("failed to create manifest: %v", err)
		}

		// create IndexReport
		ir, err := deps.libI.Index(ctx, manifest)
		if err != nil {
			t.Fatalf("failed to create IndexReport: %v", err)
		}
		if ir.Err != "" {
			t.Fatalf("IndexReport failed: %v", ir.Err)
		}

		// create VulnReport
		vr, err := deps.libV.Scan(ctx, ir)
		if err != nil {
			t.Fatalf("failed to create VulnerabilityReport: %v", err)
		}

		// load fixtures
		irPrime := claircore.IndexReport{}
		irPrimeFD, err := os.Open(fix.IR)
		if err != nil {
			t.Fatalf("failed to open IndexReport fixture: %v", err)
		}
		err = json.NewDecoder(irPrimeFD).Decode(&irPrime)
		if err != nil {
			t.Fatalf("failed to deserialize IndexReport fixture: %v", err)
		}

		vrPrime := claircore.VulnerabilityReport{}
		vrPrimeFD, err := os.Open(fix.VR)
		if err != nil {
			t.Fatalf("failed to open VulnerabilityReport fixture: %v", err)
		}
		err = json.NewDecoder(vrPrimeFD).Decode(&vrPrime)
		if err != nil {
			t.Fatalf("failed to deserialize IndexReport fixture: %v", err)
		}

		compareIndexReport(t, &irPrime, ir)
		compareVulnReport(t, &vrPrime, vr)

	}
}

func compareIndexReport(t *testing.T, irPrime *claircore.IndexReport, ir *claircore.IndexReport) {
	if !cmp.Equal(irPrime.State, ir.State) {
		t.Fatalf("state: got: %v, want: %v", irPrime.State, ir.State)
	}
	if !cmp.Equal(irPrime.Err, ir.Err) {
		t.Fatalf("err: got: %v, want: %v", irPrime.Err, ir.Err)
	}
	if !cmp.Equal(irPrime.Hash, ir.Hash, cmpopts.IgnoreUnexported(claircore.Digest{})) {
		t.Fatalf("hash: got: %v, want: %v", irPrime.Hash, ir.Hash)
	}
	if !cmp.Equal(irPrime.Success, ir.Success) {
		t.Fatalf("success: got: %v, want: %v", irPrime.Success, ir.Success)
	}
	if !cmp.Equal(irPrime.Environments, ir.Environments, cmpopts.IgnoreUnexported(claircore.Digest{})) {
		t.Fatalf("environments: got: %v, want: %v", irPrime.Environments, ir.Environments)
	}
	if !cmp.Equal(irPrime.Distributions, ir.Distributions) {
		t.Fatalf("distributions: got: %v, want: %v", irPrime.Distributions, ir.Distributions)
	}
	if !cmp.Equal(irPrime.Repositories, ir.Repositories) {
		t.Fatalf("repositories: got: %v, want: %v", irPrime.Repositories, ir.Repositories)
	}
	if !cmp.Equal(irPrime.Packages, ir.Packages) {
		t.Fatalf("packages: got: %v, want: %v", irPrime.Packages, ir.Packages)
	}
}

func compareVulnReport(t *testing.T, vrPrime *claircore.VulnerabilityReport, vr *claircore.VulnerabilityReport) {
	if !cmp.Equal(vrPrime.Distributions, vr.Distributions) {
		t.Fatalf("distributions: got: %v, want: %v", vrPrime.Distributions, vr.Distributions)
	}
	if !cmp.Equal(vrPrime.Environments, vr.Environments, cmpopts.IgnoreUnexported(claircore.Digest{})) {
		t.Fatalf("environments: got: %v, want: %v", vrPrime.Environments, vr.Environments)
	}
	if !cmp.Equal(vrPrime.Hash, vr.Hash, cmpopts.IgnoreUnexported(claircore.Digest{})) {
		t.Fatalf("hash: got: %v, want: %v", vrPrime.Hash, vr.Hash)
	}
	if !cmp.Equal(vrPrime.PackageVulnerabilities, vr.PackageVulnerabilities) {
		t.Fatalf("packagevulnerabilities: got: %v, want: %v", vrPrime.PackageVulnerabilities, vr.PackageVulnerabilities)
	}
	if !cmp.Equal(vrPrime.Packages, vr.Packages) {
		t.Fatalf("packages: got: %v, want: %v", vrPrime.Packages, vr.Packages)
	}
	if !cmp.Equal(vrPrime.Repositories, vr.Repositories) {
		t.Fatalf("repositories: got: %v, want: %v", vrPrime.Repositories, vr.Repositories)
	}
	if !cmp.Equal(vrPrime.Vulnerabilities, vr.Vulnerabilities) {
		t.Fatalf("vulnerabilities: got: %v, want: %v", vrPrime.Vulnerabilities, vr.Vulnerabilities)
	}

}
