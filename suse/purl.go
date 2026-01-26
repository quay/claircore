package suse

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
	// PURLNamespace is the namespace of SUSE RPMs.
	PURLNamespace = "opensuse"
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
				Value: ir.Distribution.DID + "-" + ir.Distribution.VersionID,
			})
		}
	}
	return p, nil
}

// ParsePURL parses an RPM PURL into a list of [claircore.IndexRecord]s.
// Preference order for distribution:
//  1. distro_cpe qualifier (converted to a [claircore.Distribution])
//  2. fallback to "distro" qualifier in the form "<name>-<versionID>" converted to a [claircore.Distribution]
func ParsePURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	var dist *claircore.Distribution
	// First try and parse a distro CPE.
	if dc := purl.Qualifiers.Map()["distro_cpe"]; dc != "" {
		if wf, err := cpe.Unbind(dc); err == nil {
			if d, err := cpeToDist(wf); err == nil && d != nil {
				dist = d
			}
		}
	}
	// Fallback to legacy "distro" qualifier.
	if dist == nil {
		distroQualifier := purl.Qualifiers.Map()["distro"]
		parts := strings.SplitN(distroQualifier, "-", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid distro qualifier: %s", distroQualifier)
		}
		switch parts[0] {
		case "sles":
			dist = ELDist(parts[1])
		case "opensuse-leap":
			dist = leapDist(parts[1])
		default:
			return nil, fmt.Errorf("invalid distro name: %s", parts[0])
		}

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
			Distribution: dist,
		},
	}, nil
}
