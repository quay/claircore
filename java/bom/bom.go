// Package bom implements consuming Red Hat's java-flavored BOMs.
package bom

import (
	"cmp"
	"context"
	"encoding/hex"
	"io"
	"iter"
	"slices"
	"strings"
	"sync"
	"unique"

	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func Load(ctx context.Context, r io.ReaderAt) (iter.Seq2[Package, error], error) {
	rd := reader.New()
	doc, err := rd.ParseStream(io.NewSectionReader(r, 0, -1))
	if err != nil {
		return nil, err
	}

	seq := func(yield func(Package, error) bool) {
		nl := doc.GetNodeList()
		roots := doc.GetRootNodes()
		for _, root := range roots {
			ids := root.GetIdentifiers()
			s := cmp.Or(
				ids[int32(sbom.SoftwareIdentifierType_CPE23)],
				ids[int32(sbom.SoftwareIdentifierType_CPE22)],
				"",
			)
			if s == "" {
				continue
			}
			wfn, err := cpe.Unbind(s)
			if err != nil {
				yield(Package{}, err)
				return
			}

			nl := nl.NodeDescendants(root.Id, 10)
			// Need to pay the cost of sorting to get deterministic output.
			slices.SortFunc(nl.Nodes, func(a, b *sbom.Node) int {
				return cmp.Compare(a.Id, b.Id)
			})

		YieldPackages:
			for _, n := range nl.GetNodes() {
				ids := n.GetIdentifiers()
				pstr, ok := ids[int32(sbom.SoftwareIdentifierType_PURL)]
				if !ok || len(n.Hashes) == 0 {
					continue
				}
				purl, err := packageurl.FromString(pstr)
				if err != nil {
					if !yield(Package{}, err) {
						return
					}
					continue
				}

				hashes := make(map[unique.Handle[string]][]byte, len(n.Hashes))
				for id, str := range n.Hashes {
					k := hashnames()[id]
					// Assume everything is encoded as hex:
					v, err := hex.DecodeString(str)
					if err != nil {
						if !yield(Package{}, err) {
							return
						}
						continue YieldPackages
					}
					hashes[k] = v
				}

				pkg := Package{
					CPE:    &wfn,
					PURL:   purl,
					Hashes: hashes,
				}
				if !yield(pkg, nil) {
					return
				}
			}
		}
	}

	return seq, nil
}

var hashnames = sync.OnceValue(func() map[int32]unique.Handle[string] {
	names := make(map[int32]unique.Handle[string], len(sbom.HashAlgorithm_name))
	for k, v := range sbom.HashAlgorithm_name {
		names[k] = unique.Make(strings.ToLower(v))
	}
	return names
})

type Package struct {
	CPE    *cpe.WFN
	PURL   packageurl.PackageURL
	Hashes map[unique.Handle[string]][]byte
}

var (
	HashSHA1   = unique.Make(`sha1`)
	HashSHA256 = unique.Make(`sha256`)
)
