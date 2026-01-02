package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

const (
	// PURLType is the type of package URL for RPM packages.
	PURLType = "rpm"
	// PURLNamespace is the namespace of AWS RPMs.
	PURLNamespace = "aws"
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
		// We don't persist the CPE in the Distribution but try it first in case it's available.
		if c := ir.Distribution.CPE.String(); c != "" {
			p.Qualifiers = append(p.Qualifiers, packageurl.Qualifier{
				Key:   "distro_cpe",
				Value: c,
			})
		}

		if ir.Distribution.DID != "" && ir.Distribution.VersionID != "" {
			p.Qualifiers = append(p.Qualifiers, packageurl.Qualifier{
				Key:   "distro",
				Value: "amzn-" + ir.Distribution.VersionID,
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
		},
		Distribution: &claircore.Distribution{},
	}
	// Prefer a distro CPE if provided.
	if dc := purl.Qualifiers.Map()["distro_cpe"]; dc != "" {
		if wf, err := cpe.Unbind(dc); err == nil {
			ir.Distribution = cpeToDistribution(wf)
			return []*claircore.IndexRecord{ir}, nil
		}
	}

	// Fallback to legacy distro qualifier parsing: "Name-VersionID".
	distroQualifier := purl.Qualifiers.Map()["distro"]
	distroParts := strings.SplitN(distroQualifier, "-", 2)
	if len(distroParts) != 2 {
		return nil, fmt.Errorf("invalid distro PURL: %s", distroQualifier)
	}
	ver := distroParts[1]
	if ver == AL1Dist.Version {
		ir.Distribution = AL1Dist
	} else {
		ir.Distribution = &claircore.Distribution{
			Name:       "Amazon Linux",
			DID:        ID,
			Version:    ver,
			VersionID:  ver,
			PrettyName: "Amazon Linux " + ver,
			CPE:        cpe.MustUnbind("cpe:o:amazon:amazon_linux:" + ver),
		}
	}
	return []*claircore.IndexRecord{ir}, nil
}
