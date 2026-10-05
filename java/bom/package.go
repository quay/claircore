package bom

import (
	"fmt"
	"net/url"
	"path"
	"unique"

	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// Package is an extracted (CPE Name, purl) pair and relevant other metadata.
type Package struct {
	CPE      *cpe.WFN
	PURL     packageurl.PackageURL
	Hashes   map[unique.Handle[string]][]byte
	Location string
}

// PopulatePackage populates "pkg" in a uniform manner.
func PopulatePackage(pkg *claircore.Package, bp Package, sbomFile string) error {
	dir := path.Dir(sbomFile)
	n := path.Join(dir, bp.Location)
	var vs []string
	for k, b := range bp.Hashes {
		vs = append(vs, fmt.Sprintf(`%s:%x`, k.Value(), b))
	}

	if bp.PURL.Namespace == "" {
		pkg.Name = bp.PURL.Name
	} else {
		pkg.Name = bp.PURL.Namespace + ":" + bp.PURL.Name
	}
	pkg.Version = bp.PURL.Version
	pkg.Kind = types.BinaryPackage
	pkg.Filepath = n
	pkg.CPE = *bp.CPE
	hint := url.Values{"hash": vs}
	if bp.CPE != nil {
		// Package.CPE is not stored. The coalescer reads this back when it
		// chooses the product repository.
		hint.Set("cpe", bp.CPE.String())
	}
	pkg.RepositoryHint = hint.Encode()
	pkg.PackageDB = `sbom:` + sbomFile

	return nil
}
