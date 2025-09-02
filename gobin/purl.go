package gobin

import (
	"context"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/purl"
)

const (
	// purlType is the type of package URL for go binaries.
	purlType = "golang"
)

func init() {
	var d *Detector
	purl.RegisterScanner(d, GeneratePURL)
	purl.RegisterParse(purlType, ParsePURL)
}

func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) packageurl.PackageURL {
	return packageurl.PackageURL{
		Type:    purlType,
		Name:    ir.Package.Name,
		Version: ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch": ir.Package.Arch,
		}),
	}
}

func ParsePURL(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error) {
	pVersion, err := ParseVersion(purl.Version)
	if err != nil {
		return nil, err
	}
	return &claircore.IndexRecord{
		Package: &claircore.Package{
			Name:              purl.Name,
			Version:           purl.Version,
			NormalizedVersion: pVersion,
			Arch:              purl.Qualifiers.Map()["arch"],
		},
		Repository: &Repository,
	}, nil
}
