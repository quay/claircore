package rhcc

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

const (
	// PURLType is the type of package URL for Red Hat Container Catalog packages.
	PURLType = "oci"
)

// GenerateOCIPURL generates an OCI PURL for a given [claircore.IndexRecord].
// Example:
// pkg:oci/ubi@sha256:dbc1e98d14a022542e45b5f22e0206d3f86b5bdf237b58ee7170c9ddd1b3a283?repository_url=registry.access.redhat.com/ubi9/ubi
func GenerateOCIPURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	purl := packageurl.PackageURL{
		Type: PURLType,
		Name: ir.Package.Name,
		// This tends to be represented as a digest but we don't persist that information
		// or use it for matching so we use the version as it is the most applicable.
		Version: ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(map[string]string{
			"arch": ir.Package.Arch,
			"tag":  ir.Package.Version,
		}),
	}
	if ir.Repository != nil && ir.Repository.Name != GoldRepo.Name {
		purl.Qualifiers = append(
			purl.Qualifiers,
			packageurl.Qualifier{Key: "container_cpe", Value: ir.Repository.CPE.String()},
		)
	}
	return purl, nil
}

// ParseOCIPURL parses an OCI PURL into a list of [claircore.IndexRecord]s.
// The matcher needs the NormalizedVersion to be set.
func ParseOCIPURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	ir := &claircore.IndexRecord{
		Package: &claircore.Package{
			Name:           purl.Name,
			Version:        purl.Version,
			Arch:           purl.Qualifiers.Map()["arch"],
			RepositoryHint: "rhcc",
			Source:         &claircore.Package{},
		},
	}

	ir.Repository = &GoldRepo
	if containerCPE, ok := purl.Qualifiers.Map()["container_cpe"]; ok {
		cpe, err := cpe.Unbind(containerCPE)
		if err != nil {
			return nil, err
		}
		ir.Repository = &claircore.Repository{
			CPE:  cpe,
			Name: cpe.String(),
			Key:  RepositoryKey,
		}
	}

	// Deal with the version.
	ir.Package.Version = purl.Version
	if tag := purl.Qualifiers.Map()["tag"]; tag != "" {
		// Prefer the tag over the version if it is present.
		ir.Package.Version = tag
	}
	sv, err := semver.NewVersion(ir.Package.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing version: %w", err)
	}
	ir.Package.NormalizedVersion = claircore.FromSemver(sv)
	return []*claircore.IndexRecord{ir}, nil
}
