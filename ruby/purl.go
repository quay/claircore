package ruby

import (
	"context"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Ruby packages.
	PURLType = "gem"
)

// GeneratePURL generates a Ruby PURL for a given [claircore.IndexRecord].
// Example: pkg:gem/rails@6.1.0
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	return packageurl.PackageURL{
		Type:    PURLType,
		Name:    ir.Package.Name,
		Version: ir.Package.Version,
	}, nil
}

// ParsePURL parses a Ruby PURL into a list of [claircore.IndexRecord]s.
// The matcher needs the NormalizedVersion to be set.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:    purl.Name,
				Version: purl.Version,
				Kind:    claircore.BINARY,
				Source:  &claircore.Package{},
			},
			Repository: &Repository,
		},
	}, nil
}
