package nodejs

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Node.js packages.
	PURLType = "npm"
)

// GeneratePURL generates a Node.js PURL for a given [claircore.IndexRecord].
// Example: pkg:npm/express@4.18.2
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	return packageurl.PackageURL{
		Type:    PURLType,
		Name:    ir.Package.Name,
		Version: ir.Package.Version,
	}, nil
}

// ParsePURL parses a Node.js PURL into a list of [claircore.IndexRecord]s.
// The matcher needs the NormalizedVersion to be set.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	v, err := semver.NewVersion(purl.Version)
	if err != nil {
		return nil, fmt.Errorf("nodejs: unable to parse version: %w", err)
	}
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:              purl.Name,
				Kind:              claircore.BINARY,
				Version:           v.String(),
				NormalizedVersion: claircore.FromSemver(v),
				Source:            &claircore.Package{},
			},
			Repository: &Repository,
		},
	}, nil
}
