package spdx

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore/purl"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
)

func TestDecoder(t *testing.T) {
	ctx := context.Background()

	t.Run("konflux-manifest", func(t *testing.T) {
		// konflux-manifest.spdx.json contains only OCI PURLs (5 total)
		// There's no standalone OCI PURL parser in the ecosystem packages,
		// so this tests that the decoder handles unknown PURL types gracefully.
		reg := purl.NewRegistry()

		d := NewDefaultDecoder(WithDecoderPURLConverter(reg))

		f, err := os.Open("testdata/decoder/konflux-manifest.spdx.json")
		if err != nil {
			t.Skip("testdata file not available:", err)
		}
		defer f.Close()

		ir, err := d.Decode(ctx, f)
		if err != nil {
			t.Fatal(err)
		}

		// OCI PURLs are not registered, so we expect no packages
		t.Logf("decoded %d packages from konflux-manifest.spdx.json (OCI PURLs not registered)", len(ir.Packages))
	})

	t.Run("konflux-syft+hermeto", func(t *testing.T) {
		// konflux-syft+hermeto.spdx.json contains:
		// - rpm/redhat PURLs (requires repository_cpes qualifier to parse)
		// - pypi PURLs (should parse successfully)
		// - oci PURLs (no parser registered)
		repoMap := map[string][]string{
			"rhel-9-for-aarch64-appstream-rpms":        {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-aarch64-appstream-source-rpms": {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-aarch64-baseos-rpms":           {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-aarch64-baseos-source-rpms":    {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-ppc64le-appstream-rpms":        {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-ppc64le-appstream-source-rpms": {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-ppc64le-baseos-rpms":           {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-ppc64le-baseos-source-rpms":    {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-s390x-appstream-rpms":          {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-s390x-appstream-source-rpms":   {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-s390x-baseos-rpms":             {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-s390x-baseos-source-rpms":      {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-x86_64-appstream-rpms":         {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-x86_64-appstream-source-rpms":  {"cpe:/a:redhat:enterprise_linux:9::appstream"},
			"rhel-9-for-x86_64-baseos-rpms":            {"cpe:/o:redhat:enterprise_linux:9::baseos"},
			"rhel-9-for-x86_64-baseos-source-rpms":     {"cpe:/o:redhat:enterprise_linux:9::baseos"},
		}
		reg := purl.NewRegistry()
		reg.RegisterPurlType(python.PURLType, purl.NoneNamespace, python.ParsePURL)
		reg.RegisterPurlType(rhel.PURLType, rhel.PURLNamespace, rhel.ParseRPMPURL, mockTransformer(repoMap))

		d := NewDefaultDecoder(WithDecoderPURLConverter(reg))

		f, err := os.Open("testdata/decoder/konflux-syft+hermeto.spdx.json")
		if err != nil {
			t.Skip("testdata file not available:", err)
		}
		defer f.Close()

		ir, err := d.Decode(ctx, f)
		if err != nil {
			t.Fatal(err)
		}

		//   1511 valid rpm/redhat PURLs
		// -  188 invalid valid rpm/redhat PURLs (no repository_id)
		// +   18 valid pypi PURLs
		// = 1341 packages
		if len(ir.Packages) != 1341 {
			t.Errorf("expected %d packages, got %d", 1341, len(ir.Packages))
		}
		t.Logf("decoded %d packages, %d distributions, %d repositories",
			len(ir.Packages), len(ir.Distributions), len(ir.Repositories))
	})
}

func TestDecoderNoPURLConverter(t *testing.T) {
	ctx := context.Background()

	// Decoder without a PURL converter should return an empty IndexReport.
	d := NewDefaultDecoder()

	f, err := os.Open("testdata/decoder/konflux-manifest.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ir, err := d.Decode(ctx, f)
	if err != nil {
		t.Fatal(err)
	}

	// Without PURL converter, should have no packages
	if len(ir.Packages) != 0 {
		t.Errorf("expected no packages without PURL converter, got %d", len(ir.Packages))
	}
}

func mockTransformer(repoMap map[string][]string) func(ctx context.Context, p *packageurl.PackageURL) error {
	return func(ctx context.Context, p *packageurl.PackageURL) error {
		// It has already been transformed, or doesn't need to be.
		if _, ok := p.Qualifiers.Map()["repository_cpes"]; ok {
			return nil
		}
		repoid, ok := p.Qualifiers.Map()["repository_id"]
		if !ok {
			return nil
		}
		if cpes, ok := repoMap[repoid]; ok {
			cpesStr := strings.Join(cpes, ",")
			p.Qualifiers = append(p.Qualifiers, packageurl.Qualifier{Key: "repository_cpes", Value: cpesStr})
		}
		return nil
	}
}
