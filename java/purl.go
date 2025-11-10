package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Java packages.
	PURLType = "maven"
)

// GeneratePURL generates a Maven PURL for a given [claircore.IndexRecord].
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	// The PURL examples in the spec show that the group ID is used
	// as the namespace for Maven PURLs, so split the package name on the colon.
	// https://github.com/package-url/purl-spec?tab=readme-ov-file#some-purl-examples
	parts := strings.SplitN(ir.Package.Name, ":", 2)
	if len(parts) != 2 {
		return packageurl.PackageURL{}, fmt.Errorf("invalid package name: %s", ir.Package.Name)
	}
	return packageurl.PackageURL{
		Type:      PURLType,
		Namespace: parts[0],
		Name:      parts[1],
		Version:   ir.Package.Version,
	}, nil
}

// ParsePURL parses a Maven PURL into a list of [claircore.IndexRecord]s.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:    purl.Namespace + ":" + purl.Name,
				Version: purl.Version,
				Kind:    claircore.BINARY,
			},
			Repository: &Repository,
		},
	}, nil
}
