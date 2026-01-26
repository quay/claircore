package photon

import (
	"context"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
)

const (
	// PURLType is the type of package URL for RPM packages.
	PURLType = "rpm"
	// PURLNamespace is the namespace of photon RPMs.
	PURLNamespace = "photon"
)

// GeneratePURL generates an RPM PURL for a given [claircore.IndexRecord].
func GeneratePURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	p := packageurl.PackageURL{
		Type:      PURLType,
		Namespace: PURLNamespace,
		Name:      ir.Package.Name,
		Version:   ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch": ir.Package.Arch,
		}),
	}
	if ir.Distribution != nil {
		if ir.Distribution.DID != "" && ir.Distribution.VersionID != "" {
			p.Qualifiers = append(p.Qualifiers, packageurl.Qualifier{
				Key:   "distro",
				Value: "photon-" + ir.Distribution.VersionID,
			})
		}
	}
	return p, nil
}

// ParsePURL parses an RPM PURL into a list of [claircore.IndexRecord]s.
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	ir := &claircore.IndexRecord{
		Package: &claircore.Package{
			Name:    purl.Name,
			Version: purl.Version,
			Arch:    purl.Qualifiers.Map()["arch"],
			Kind:    claircore.BINARY,
			Source:  &claircore.Package{},
		},
		Distribution: &claircore.Distribution{},
	}
	distroQualifier := purl.Qualifiers.Map()["distro"]
	distroParts := strings.SplitN(distroQualifier, "-", 2)
	if len(distroParts) != 2 {
		return nil, fmt.Errorf("invalid distro PURL: %s", distroQualifier)
	}
	ir.Distribution = releaseToDist(Release(distroParts[1]))
	return []*claircore.IndexRecord{ir}, nil
}
