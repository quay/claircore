package alpine

import (
	"context"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for Alpine APKs.
	PURLType = "apk"
	// PURLNamespace is the namespace of Alpine APKs.
	PURLNamespace = "alpine"
	// PURLDistroQualifier is the qualifier key for the distribution.
	PURLDistroQualifier = "distro"
)

// GeneratePURL generates a PURL for an Alpine APK package in the format:
// pkg:apk/alpine/<package-name>@<package-version>?arch=<package-arch>&distro=<distro-name>-<distro-version>
func GeneratePURL(ctx context.Context, r *claircore.IndexRecord) (packageurl.PackageURL, error) {
	var distro string
	if r.Distribution != nil {
		distro = r.Distribution.Name + "-" + r.Distribution.Version
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

// ParsePURL parses a PURL for an Alpine APK package into a list of IndexRecords.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	d := distoToDistribution(purl.Qualifiers.Map()[PURLDistroQualifier])
	return []*claircore.IndexRecord{
		{
			Package: &claircore.Package{
				Name:    purl.Name,
				Version: purl.Version,
				Kind:    claircore.BINARY,
				Arch:    purl.Qualifiers.Map()["arch"],
				Source:  &claircore.Package{},
			},
			Distribution: d,
		},
	}, nil
}

// DistributionFromPURL converts a PURL string to a *claircore.Distribution.
// distro strings are expected to be in the form "alpine-<version>".
// The distro format is discussed here: https://github.com/package-url/purl-spec/issues/423
func distoToDistribution(distro string) *claircore.Distribution {
	// split the distro string into name and version
	d := strings.Split(distro, "-")
	if d[1] == edgeDist.VersionID {
		return edgeDist
	}
	v := strings.Split(d[1], ".")
	if len(v) < 2 {
		// There are some cases where the version is 3 parts but the patch doesn't
		// influence addressability so we can ignore it.
		return nil
	}
	maj, err := strconv.Atoi(v[0])
	if err != nil {
		return nil
	}
	min, err := strconv.Atoi(v[1])
	if err != nil {
		return nil
	}
	dist := stableRelease{maj, min}.Distribution()
	return dist
}
