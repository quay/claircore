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

// Package is an extracted purl and the product CPEs that provide it.
// CPEs is empty when the purl is part of the application but no product
// provides it.
type Package struct {
	CPEs     []cpe.WFN
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
	hint := url.Values{"hash": vs}
	// Package.CPE is not stored, and it only holds one name. The coalescer
	// reads every cpe value back when it chooses product repositories.
	for _, w := range bp.CPEs {
		hint.Add("cpe", w.String())
	}
	if len(bp.CPEs) == 1 {
		pkg.CPE = bp.CPEs[0]
	}
	pkg.RepositoryHint = hint.Encode()
	pkg.PackageDB = `sbom:` + sbomFile

	return nil
}
