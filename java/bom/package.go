package bom

import (
	"encoding/hex"
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

// PopulatePackage fills pkg from an SBOM component.
func PopulatePackage(pkg *claircore.Package, bp Package, sbomFile string) error {
	dir := path.Dir(sbomFile)
	n := path.Join(dir, bp.Location)

	if bp.PURL.Namespace == "" {
		pkg.Name = bp.PURL.Name
	} else {
		pkg.Name = bp.PURL.Namespace + ":" + bp.PURL.Name
	}
	pkg.Version = bp.PURL.Version
	pkg.Kind = types.BinaryPackage
	pkg.Filepath = n
	// Package.CPE is not stored, and it only holds one name. The coalescer
	// reads every cpe value back when it chooses product repositories.
	hint := url.Values{}
	for _, w := range bp.CPEs {
		hint.Add("cpe", w.String())
	}
	// path is the layer path a JAR scan should not also report. The coalescer
	// reads it back with the component digests.
	if bp.Location != "" {
		hint.Set("path", n)
	}
	if sum := bp.Hashes[HashSHA1]; len(sum) != 0 {
		hint.Set("sha1", hex.EncodeToString(sum))
	}
	if sum := bp.Hashes[HashSHA256]; len(sum) != 0 {
		hint.Set("sha256", hex.EncodeToString(sum))
	}
	if len(bp.CPEs) == 1 {
		pkg.CPE = bp.CPEs[0]
	}
	pkg.RepositoryHint = hint.Encode()
	// package_scanartifact is keyed by package_db. The component location
	// keeps two copies of one coordinate in the same document as two rows.
	pkg.PackageDB = `sbom:` + sbomFile
	if bp.Location != "" {
		pkg.PackageDB += ":" + bp.Location
	}

	return nil
}
