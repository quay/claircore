package gobin

import (
	"context"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for go binaries.
	PURLType = "golang"
)

// GeneratePURL generates a Go binary PURL for a given [claircore.IndexRecord].
// Example: pkg:golang/google.golang.org/genproto#googleapis/api/annotations?arch=x86_64
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	// Split the Go import path into namespace (domain), module name and package subpath.
	ns, name, subpath := splitGoModule(ir.Package.Name)
	return packageurl.PackageURL{
		Type:      PURLType,
		Namespace: ns,
		Name:      name,
		Version:   ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch": ir.Package.Arch,
		}),
		Subpath: subpath,
	}, nil
}

// ParsePURL parses a Go binary PURL into a list of [claircore.IndexRecord]s.
// The matcher needs the NormalizedVersion to be set and to be semver.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	pVersion, err := ParseVersion(purl.Version)
	if err != nil {
		return nil, err
	}
	fullName := purl.Name
	if purl.Namespace != "" {
		fullName = purl.Namespace + "/" + fullName
	}
	if purl.Subpath != "" {
		fullName = fullName + "/" + purl.Subpath
	}
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:              fullName,
				Version:           purl.Version,
				Kind:              claircore.BINARY,
				NormalizedVersion: pVersion,
				Arch:              purl.Qualifiers.Map()["arch"],
			},
			Repository: &Repository,
		},
	}, nil
}

// splitGoModule splits a Go import path into:
//   - domain namespace (the first path segment, e.g., "google.golang.org")
//   - package name (the second path segment, e.g., "genproto")
//   - package subpath (all remaining segments, e.g., "googleapis/api/annotations")
//
// Single-segment names yield an empty namespace and subpath.
func splitGoModule(full string) (namespace, name, subpath string) {
	parts := strings.Split(full, "/")
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return "", parts[0], ""
	default:
		return parts[0], parts[1], strings.Join(parts[2:], "/")
	}
}
