package gobin

import (
	"context"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for go binaries.
	PURLType = "golang"
)

func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	return packageurl.PackageURL{
		Type:    PURLType,
		Name:    ir.Package.Name,
		Version: ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch": ir.Package.Arch,
		}),
	}, nil
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
			Kind:              claircore.BINARY,
			NormalizedVersion: pVersion,
			Arch:              purl.Qualifiers.Map()["arch"],
		},
		Repository: &Repository,
	}, nil
}
