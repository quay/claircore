package rhel

import (
	"context"
	"net/url"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
	"github.com/quay/claircore/toolkit/types/cpe"
)

const (
	// PURLType is the type of package URL for RPMs.
	PURLType = "rpm"

	// PURLNamespace is the namespace of Red Hat RPMs.
	PURLNamespace = "redhat"
)

func GenerateRPMPURL(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
	qs := map[string]string{
		"arch": ir.Package.Arch,
	}
	if ir.Repository != nil {
		// Encode to keep the qualifier syntactically safe
		qs["repository_cpes"] = url.QueryEscape(ir.Repository.CPE.String())
	}
	if ir.Package.Module != "" {
		qs["rpmmod"] = ir.Package.Module
	}
	if ir.Distribution != nil {
		qs["distro"] = ir.Distribution.Name
	}
	return packageurl.PackageURL{
		Type:       PURLType,
		Namespace:  PURLNamespace,
		Name:       ir.Package.Name,
		Version:    ir.Package.Version,
		Qualifiers: packageurl.QualifiersFromMap(qs),
	}, nil
}

// ParseRPMPURL parses an RPM PURL into a list of IndexRecords.
// It expects the repository_cpes qualifier to be set to a comma-separated list of CPEs.
// No repository_cpes qualifier means no IndexRecords are returned.
func ParseRPMPURL(ctx context.Context, purl packageurl.PackageURL) ([]*claircore.IndexRecord, error) {
	v, err := rpmver.Parse(purl.Version)
	if err != nil {
		return nil, err
	}

	out := []*claircore.IndexRecord{}

	repositoryCPEs, ok := purl.Qualifiers.Map()["repository_cpes"]
	if !ok {
		return out, nil
	}

	for CPEstring := range strings.SplitSeq(repositoryCPEs, ",") {
		CPEstring, err := url.QueryUnescape(CPEstring)
		if err != nil {
			return nil, err
		}

		repoCPE, err := cpe.Unbind(CPEstring)
		if err != nil {
			return nil, err
		}

		// TODO: Agree on how to serialize the Distribution object
		out = append(out, &claircore.IndexRecord{
			Package: &claircore.Package{
				Name:    purl.Name,
				Version: v.EVR(),
				Module:  purl.Qualifiers.Map()["rpmmod"],
				Arch:    purl.Qualifiers.Map()["arch"],
			},
			Repository: &claircore.Repository{
				CPE:  repoCPE,
				Name: repoCPE.String(),
				Key:  repositoryKey,
			},
		})
	}

	return out, nil
}
