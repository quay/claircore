package bom

import (
	"fmt"
	"net/url"
	"path"
	"strings"
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

	group, artifact, ok := strings.Cut(bp.PURL.Name, "/")
	if !ok {
		pkg.Name = bp.PURL.Name
	} else {
		pkg.Name = group + ":" + artifact
	}
	pkg.Version = bp.PURL.Version
	pkg.Kind = types.BinaryPackage
	pkg.Filepath = n
	pkg.CPE = *bp.CPE
	pkg.RepositoryHint = (url.Values{"hash": vs}).Encode()
	pkg.PackageDB = `sbom:` + sbomFile

	return nil
}
