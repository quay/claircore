package ubuntu

import (
	"context"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Ubuntu packages.
	PURLType = "deb"
	// PURLNamespace is the namespace of Ubuntu packages.
	PURLNamespace = "ubuntu"
	// PURLDistroQualifier is the qualifier key for the distribution.
	PURLDistroQualifier = "distro"
)

// GeneratePURL generates a PURL for a Ubuntu package in the format:
// pkg:deb/ubuntu/<package-name>@<package-version>?arch=<package-arch>&distro=ubuntu-<distro-versionID>
func GeneratePURL(ctx context.Context, r *claircore.IndexRecord) (packageurl.PackageURL, error) {
	var distro string
	if r.Distribution != nil {
		// This completely ignores the version code name e.g. "ubuntu-24.04".
		distro = "ubuntu-" + r.Distribution.VersionID
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

// ParsePURL parses a PURL for a Ubuntu package into a list of IndexRecords.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	dq := purl.Qualifiers.Map()[PURLDistroQualifier]
	distroParts := strings.SplitN(dq, "-", 2)
	if len(distroParts) != 2 {
		return nil, fmt.Errorf("invalid distro PURL: %s", dq)
	}
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:    purl.Name,
				Version: purl.Version,
				Arch:    purl.Qualifiers.Map()["arch"],
				Kind:    claircore.BINARY,
				Source:  &claircore.Package{},
			},
			Distribution: &claircore.Distribution{
				Name:       "Ubuntu",
				DID:        "ubuntu",
				VersionID:  distroParts[1],
				PrettyName: "Ubuntu " + distroParts[1],
			},
		},
	}, nil
}
