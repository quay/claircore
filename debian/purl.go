package debian

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Debian packages.
	PURLType = "deb"
	// PURLNamespace is the namespace of Debian packages.
	PURLNamespace = "debian"
	// PURLDistroQualifier is the qualifier key for the distribution.
	PURLDistroQualifier = "distro"
)

// GeneratePURL generates a PURL for a Debian package in the format:
// pkg:deb/debian/<package-name>@<package-version>?arch=<package-arch>&distro=debian-<distro-versionID>
func GeneratePURL(ctx context.Context, r *claircore.IndexRecord) (packageurl.PackageURL, error) {
	var distro string
	if r.Distribution != nil {
		// This completely ignores the version code name e.g. "debian-13".
		distro = "debian-" + r.Distribution.VersionID
	}
	return packageurl.PackageURL{
		Type:      PURLType,
		Namespace: PURLNamespace,
		Name:      r.Package.Name,
		Version:   r.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch":              r.Package.Arch,
			PURLDistroQualifier: distro,
		}),
	}, nil
}

// ParsePURL parses a PURL for a Debian package into a list of IndexRecords.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	dq := purl.Qualifiers.Map()[PURLDistroQualifier]
	distroParts := strings.SplitN(dq, "-", 2)
	if len(distroParts) != 2 {
		return nil, fmt.Errorf("invalid distro PURL: %s", dq)
	}
	_, err := strconv.Atoi(distroParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid distro version: %s", distroParts[1])
	}
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:    purl.Name,
				Version: purl.Version,
				Arch:    purl.Qualifiers.Map()["arch"],
				Kind:    claircore.BINARY,
			},
			Distribution: &claircore.Distribution{
				Name:      "Debian GNU/Linux",
				VersionID: distroParts[1],
				DID:       "debian",
			},
		},
	}, nil
}
