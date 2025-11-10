package python

import (
	"context"
	"fmt"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/pep440"
)

const (
	// PURLType is the type of package URL for Python packages.
	PURLType = "pypi"
)

// GeneratePURL generates a PyPI PURL for a given [claircore.IndexRecord].
// Example: pkg:pypi/django@1.11.1
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	return packageurl.PackageURL{
		Type:    PURLType,
		Name:    ir.Package.Name,
		Version: ir.Package.Version,
	}, nil
}

// ParsePURL parses a PyPI PURL into a list of [claircore.IndexRecord]s.
// The matcher needs the NormalizedVersion to be set, and it to be pep440.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	v, err := pep440.Parse(purl.Version)
	if err != nil {
		return nil, fmt.Errorf("python: unable to parse version: %w", err)
	}
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:              purl.Name,
				Version:           v.String(),
				NormalizedVersion: v.Version(),
				Kind:              claircore.BINARY,
			},
			Repository: &Repository,
		},
	}, nil
}
