package rhel

import (
	"context"
	"net/url"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/purl"
)

const (
	// purlType is the type of package URL for go binaries.
	purlType      = "rpm"
	purlNamespace = "redhat"
)

func init() {
	var s *PackageScanner
	purl.RegisterScanner(s, GenerateRPMPURL)
}

func GenerateRPMPURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	qs := map[string]string{
		"arch": ir.Package.Arch,
	}
	if ir.Repository != nil {
		// Encode to keep the qualifier syntactically safe
		qs["repository_cpe"] = url.QueryEscape(ir.Repository.CPE.String())
	}
	if ir.Package.Module != "" {
		qs["rpmmod"] = ir.Package.Module
	}
	return packageurl.PackageURL{
		Type:       purlType,
		Namespace:  purlNamespace,
		Name:       ir.Package.Name,
		Version:    ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(qs),
	}, nil
}
