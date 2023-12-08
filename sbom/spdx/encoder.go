package spdx

import (
	"bytes"
	"context"
	"fmt"
	spdxjson "github.com/spdx/tools-golang/json"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/sbom"

	"github.com/spdx/tools-golang/spdx/common"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type Version string

const (
	V2_3 Version = "v2.3"
)

type Format string

const JSON Format = "json"

type Creator struct {
	Creator string
	// In accordance to the SPDX v2 spec, CreatorType should be one of "Person", "Organization", or "Tool"
	CreatorType string
}

var _ sbom.Encoder = (*Encoder)(nil)

type Encoder struct {
	Version           Version
	Format            Format
	Creators          []Creator
	DocumentName      string
	DocumentNamespace string
	DocumentComment   string
}

// Encode encodes a claircore IndexReport to an io.Reader.
// We first convert the IndexReport to an SPDX doc of the latest version, then
// convert that doc to the specified version. We assume there's no data munging
// going from latest to the specified version.
func (e *Encoder) Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error) {
	spdx, err := e.parseIndexReport(ctx, ir)
	if err != nil {
		return nil, err
	}

	// TODO(blugo): support SPDX versions before 2.3
	var tmpConverterDoc common.AnyDocument
	switch e.Version {
	case V2_3:
		// parseIndexReport currently returns a v2_3.Document so do nothing
		tmpConverterDoc = spdx
	default:
		return nil, fmt.Errorf("unknown SPDX version: %v", e.Version)
	}

	switch e.Format {
	case JSON:
		buf := &bytes.Buffer{}
		if err := spdxjson.Write(tmpConverterDoc, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	return nil, fmt.Errorf("unknown requested format: %v", e.Format)
}

func (e *Encoder) parseIndexReport(ctx context.Context, ir *claircore.IndexReport) (*v2_3.Document, error) {
	creatorInfo := e.Creators
	spdxCreators := make([]v2common.Creator, len(creatorInfo))
	for i, creator := range creatorInfo {
		spdxCreators[i].Creator = creator.Creator
		spdxCreators[i].CreatorType = creator.CreatorType
	}

	// Initial metadata
	out := &v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      e.DocumentName,
		DocumentNamespace: e.DocumentNamespace,
		CreationInfo: &v2_3.CreationInfo{
			Creators: spdxCreators,
			Created:  time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: e.DocumentComment,
	}

	pkgMap := map[int]*v2_3.Package{}
	var pkgIds []int
	distMap := map[int]*v2_3.Package{}
	var distIds []int
	repoMap := map[int]*v2_3.Package{}
	var repoIds []int
	pkgRels := map[int][]*v2_3.Relationship{}
	for _, r := range ir.IndexRecords() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		rPkgId, err := strconv.Atoi(r.Package.ID)
		if err != nil {
			return nil, err
		}

		pkg, ok := pkgMap[rPkgId]
		// Record the package if we haven't seen it yet.
		if !ok {
			pkgDB := ""
			for _, env := range ir.Environments[r.Package.ID] {
				if env.PackageDB != "" {
					pkgDB = env.PackageDB
					break
				}
			}

			pkgPurpose := "APPLICATION"
			if r.Package.Kind != claircore.BINARY {
				pkgPurpose = "SOURCE"
			}

			pkg = newSpdxPackageFromPackage(r.Package)
			pkg.PackageFileName = pkgDB
			pkg.FilesAnalyzed = true
			pkg.PrimaryPackagePurpose = pkgPurpose

			pkgMap[rPkgId] = pkg
			pkgIds = append(pkgIds, rPkgId)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				rSrcPkgId, err := strconv.Atoi(r.Package.Source.ID)
				if err != nil {
					return nil, err
				}

				srcPkg, ok := pkgMap[rSrcPkgId]
				// Record the source package if we haven't seen it yet.
				if !ok {
					srcPkg = newSpdxPackageFromPackage(r.Package.Source)
					srcPkg.PrimaryPackagePurpose = "SOURCE"
					pkgMap[rSrcPkgId] = srcPkg
					pkgIds = append(pkgIds, rSrcPkgId)
				}

				rel := &v2_3.Relationship{
					RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         v2common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				}
				pkgRels[rPkgId] = append(pkgRels[rPkgId], rel)
			}
		} else if pkg.PrimaryPackagePurpose == "SOURCE" {
			// If we recorded a source package when we found it as an r.Package.Source,
			// we need to record any missing information we didn't know about previously.
			pkg.FilesAnalyzed = true
			if pkg.PackageFileName == "" {
				pkgDB := ""
				for _, env := range ir.Environments[r.Package.ID] {
					if env.PackageDB != "" {
						pkgDB = env.PackageDB
						break
					}
				}
				pkg.PackageFileName = pkgDB
			}
		}

		// Record Distributions for this package.
		if r.Distribution != nil {
			rDistId, err := strconv.Atoi(r.Distribution.ID)
			if err != nil {
				return nil, err
			}

			dist, ok := distMap[rDistId]
			// Record the Distribution if we haven't seen it yet.
			if !ok {
				dist = newSpdxPackageFromDistribution(r.Distribution)
				distMap[rDistId] = dist
				distIds = append(distIds, rDistId)
			}

			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			pkgRels[rPkgId] = append(pkgRels[rPkgId], rel)
		}

		// Record Repositories for this package.
		if r.Repository != nil {
			rRepoId, err := strconv.Atoi(r.Repository.ID)
			if err != nil {
				return nil, err
			}

			repo, ok := repoMap[rRepoId]
			// Record the Repository if we haven't seen it yet.
			if !ok {
				repo = newSpdxPackageFromRepository(r.Repository)

				repoMap[rRepoId] = repo
				repoIds = append(repoIds, rRepoId)
			}

			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			pkgRels[rPkgId] = append(pkgRels[rPkgId], rel)
		}
	}

	// Now that we have all the data necessary to create the SPDX document,
	// we need to order it since the IndexRecords aren't in a deterministic order.
	// This is particular helpful for testing, but it wouldn't be unreasonable
	// for a user to want to diff different versions of an SPDX of the same IndexReport.
	sort.Ints(pkgIds)
	for _, id := range pkgIds {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkg := pkgMap[id]
		out.Packages = append(out.Packages, pkg)

		rels := pkgRels[id]
		slices.SortFunc(rels, cmpRelationship)
		out.Relationships = append(out.Relationships, rels...)
	}

	sort.Ints(distIds)
	for _, id := range distIds {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		dist := distMap[id]
		out.Packages = append(out.Packages, dist)
	}

	sort.Ints(repoIds)
	for _, id := range repoIds {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		repo := repoMap[id]
		out.Packages = append(out.Packages, repo)
	}

	return out, nil
}

func newSpdxPackageFromPackage(p *claircore.Package) *v2_3.Package {
	pkg := &v2_3.Package{
		PackageName:             p.Name,
		PackageSPDXIdentifier:   v2common.ElementID("Package-" + p.ID),
		PackageVersion:          p.Version,
		PackageDownloadLocation: "NOASSERTION",
	}
	return pkg
}

func newSpdxPackageFromDistribution(d *claircore.Distribution) *v2_3.Package {
	var extRefs []*v2_3.PackageExternalReference

	if d.CPE.String() != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "cpe23Type",
			Locator:  d.CPE.String(),
		})
	}

	if d.DID != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  "did",
			Locator:  d.DID,
		})
	}

	if d.VersionID != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  "version_id",
			Locator:  d.VersionID,
		})
	}

	if d.PrettyName != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  "pretty_name",
			Locator:  d.PrettyName,
		})
	}

	dist := &v2_3.Package{
		PackageName:               d.Name,
		PackageSPDXIdentifier:     v2common.ElementID("Distribution-" + d.ID),
		PackageVersion:            d.Version,
		PackageDownloadLocation:   "NOASSERTION",
		FilesAnalyzed:             true,
		PackageExternalReferences: extRefs,
		PackageSummary:            "distribution",
		PrimaryPackagePurpose:     "OPERATING-SYSTEM",
	}

	return dist
}

func newSpdxPackageFromRepository(r *claircore.Repository) *v2_3.Package {
	var extRefs []*v2_3.PackageExternalReference
	if r.CPE.String() != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "cpe23Type",
			Locator:  r.CPE.String(),
		})
	}

	if r.URI != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  "uri",
			Locator:  r.URI,
		})
	}

	if r.Key != "" {
		extRefs = append(extRefs, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  "key",
			Locator:  r.Key,
		})
	}

	repo := &v2_3.Package{
		PackageName:               r.Name,
		PackageSPDXIdentifier:     v2common.ElementID("Repository-" + r.ID),
		PackageDownloadLocation:   "NOASSERTION",
		FilesAnalyzed:             true,
		PackageSummary:            "repository",
		PackageExternalReferences: extRefs,
		PrimaryPackagePurpose:     "OTHER",
	}

	return repo
}

func cmpRelationship(a, b *v2_3.Relationship) int {
	refBCpm := strings.Compare(string(a.RefB.ElementRefID), string(b.RefB.ElementRefID))
	if refBCpm != 0 {
		return refBCpm
	}

	return strings.Compare(a.Relationship, b.Relationship)
}
