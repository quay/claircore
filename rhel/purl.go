package rhel

import (
	"context"
	"net/url"

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
		qs["repository_cpe"] = url.QueryEscape(ir.Repository.CPE.String())
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

func ParseRPMPURL(ctx context.Context, purl packageurl.PackageURL) (*claircore.IndexRecord, error) {
	v, err := rpmver.Parse(purl.Version)
	if err != nil {
		return nil, err
	}

	var CPEstring string
	// TODO (crozzy): How do we want to map the repoid to the CPE?
	// Where do we want to hang the updater? Where should the config live?
	// repoid, ok := purl.Qualifiers.Map()["repository_id"]
	// if ok {
	// 	CPEstring = updater.GetOne(ctx, repoid)
	// }

	CPEstring, err = url.QueryUnescape(purl.Qualifiers.Map()["repository_cpe"])
	if err != nil {
		return nil, err
	}

	repoCPE, err := cpe.Unbind(CPEstring)
	if err != nil {
		return nil, err
	}
	// TODO: Agree on how to serialize the Distribution object
	return &claircore.IndexRecord{
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
	}, nil
}
