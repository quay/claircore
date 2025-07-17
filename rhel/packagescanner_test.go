package rhel

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/rpmtest"
)

//go:generate -command fetch go run github.com/quay/claircore/test/cmd/fetch-container-rpm-manifest
//go:generate fetch -o testdata/package/ubi8_ubi.txtar ubi8/ubi
//go:generate fetch -o testdata/package/ubi9_ubi.txtar ubi9/ubi
//go:generate fetch -o testdata/package/ubi9_httpd-24.txtar ubi9/httpd-24

func TestPackageDetection(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	ms, err := filepath.Glob("testdata/package/*.txtar")
	if err != nil {
		panic("programmer error") // static glob
	}

	a := test.NewCachedArena(t)
	t.Cleanup(func() {
		if err := a.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	// BUG(hank) The repoid information seems to not currently exist in Pyxis.
	// The tests here use a hard-coded allowlist.
	repoAllow := map[string][]string{
		"registry.access.redhat.com/ubi9/httpd-24": {"RHEL-9.0.0-updates-20220503.2-AppStream", "RHEL-9.0.0-updates-20220503.2-BaseOS"},
	}
	s := new(PackageScanner)

	for _, m := range ms {
		ar, err := rpmtest.OpenArchive(ctx, m)
		if err != nil {
			t.Error(err)
			continue
		}
		ar.Tests(ctx, a, repoAllow, s.Scan)(t)
	}
}

// TestPackageScannerDNFWrapLogic verifies that PackageScanner.Scan correctly
// uses the FromDNFHint field in content manifests to determine whether packages
// get repoid information.
func TestPackageScannerDNFWrapLogic(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	tests := []struct {
		name             string
		layerPath        string
		expectRepoidHint bool
		description      string
	}{
		{
			name:             "FromDNFHintTrue",
			layerPath:        "testdata/layer-dnf-hint-true.tar",
			expectRepoidHint: true,
			description:      "When FromDNFHint is true, packages should have repoid in the RepositoryHint field",
		},
		{
			name:             "FromDNFHintAbsent",
			layerPath:        "testdata/layer-dnf-hint-absent.tar",
			expectRepoidHint: false,
			description:      "When FromDNFHint field is absent, packages should not have repoid in the RepositoryHint field",
		},
		{
			name:             "ContentManifestAbsent",
			layerPath:        "testdata/layer-content-sets-missing.tar",
			expectRepoidHint: true,
			description:      "When ContentManifest is absent, packages should have repoid in the RepositoryHint field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := zlog.Test(ctx, t)

			// Create layer from tar file
			f, err := os.Open(tt.layerPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    `sha256:` + "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
				URI:       `file:///dev/null`,
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			}
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})

			// Run the actual package scanner
			scanner := &PackageScanner{}
			packages, err := scanner.Scan(ctx, &l)
			if err != nil {
				t.Fatalf("PackageScanner.Scan failed: %v", err)
			}

			// We should find packages from the RPM DB
			if len(packages) == 0 {
				t.Fatalf("Expected to find some packages")
			}

			// Check if any packages have the repoid key in RepositoryHint
			packagesWithRepoid := 0
			for _, pkg := range packages {
				if pkg.RepositoryHint != "" {
					values, err := url.ParseQuery(pkg.RepositoryHint)
					if err != nil {
						continue
					}
					if len(values["repoid"]) > 0 {
						packagesWithRepoid++
					}
				}
			}

			if tt.expectRepoidHint && packagesWithRepoid == 0 {
				t.Errorf("Expected some packages to have repoid hints, but found none")
			}

			if !tt.expectRepoidHint && packagesWithRepoid > 0 {
				t.Errorf("Expected no packages to have repoid hints, but found %d", packagesWithRepoid)

			}
		})
	}
}
