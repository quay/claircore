package spdx

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/common"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/quay/claircore"
	"github.com/quay/claircore/sbom"
)

// Version describes the SPDX version to target.
type Version string

const (
	V2_3 Version = "v2.3"
)

// Format describes the data format for the SPDX document.
type Format string

const JSONFormat Format = "json"

// Option is a type for setting optional fields for the Encoder.
type Option func(*Encoder)

// Creator describes the creator of the SPDX document that will be produced from the encoding.
type Creator struct {
	// Creator is the value of the [Creator] relationship.
	Creator string
	// CreatorType is the key of the [Creator] relationship.
	// In accordance to the SPDX v2 spec, CreatorType should be one of "Person", "Organization", or "Tool".
	CreatorType string
}

var _ sbom.Encoder = (*Encoder)(nil)

// Encoder defines an SPDX encoder and accepts certain values from the caller
// to use in the SPDX document.
type Encoder struct {
	// The target SPDX version in which to encode.
	Version Version
	// The data format in which to encode.
	Format Format
	// The SPDX document creator information.
	Creators []Creator
	// The SPDX document name field.
	DocumentName string
	// The SPDX document namespace field.
	DocumentNamespace string
	// The SPDX document comment field.
	DocumentComment string
}

// NewDefaultEncoder creates an Encoder with default values and sets optional
// fields based on the provided options.
func NewDefaultEncoder(options ...Option) *Encoder {
	e := &Encoder{
		Version: V2_3,
		Format:  JSONFormat,
		Creators: []Creator{
			{
				Creator:     "Claircore-" + getVersion(),
				CreatorType: "Tool",
			},
		},
	}

	for _, opt := range options {
		opt(e)
	}

	return e
}

// WithDocumentName is used to set the SPDX document name field.
func WithDocumentName(name string) Option {
	return func(e *Encoder) {
		e.DocumentName = name
	}
}

// WithDocumentNamespace is used to set the SPDX document namespace field.
func WithDocumentNamespace(namespace string) Option {
	return func(e *Encoder) {
		e.DocumentNamespace = namespace
	}
}

// WithDocumentComment is used to set the SPDX document comment field.
func WithDocumentComment(comment string) Option {
	return func(e *Encoder) {
		e.DocumentComment = comment
	}
}

// Encode encodes a [claircore.IndexReport] that writes to w.
// We first convert the IndexReport to an SPDX doc of the latest version, then
// convert that doc to the specified version. We assume there's no data munging
// going from latest to the specified version.
func (e *Encoder) Encode(ctx context.Context, w io.Writer, ir *claircore.IndexReport) error {
	spdx, err := e.parseIndexReport(ctx, ir)
	if err != nil {
		return err
	}

	// TODO(blugo): support SPDX versions before 2.3
	var tmpConverterDoc common.AnyDocument
	switch e.Version {
	case V2_3:
		// parseIndexReport currently returns a v2_3.Document so do nothing
		tmpConverterDoc = spdx
	default:
		return fmt.Errorf("unknown SPDX version: %v", e.Version)
	}

	switch e.Format {
	case JSONFormat:
		if err := spdxjson.Write(tmpConverterDoc, w); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("unknown requested format: %v", e.Format)
}

func (e *Encoder) parseIndexReport(ctx context.Context, ir *claircore.IndexReport) (*v2_3.Document, error) {
	creators := make([]v2common.Creator, len(e.Creators))
	for i, creator := range e.Creators {
		creators[i] = v2common.Creator{
			Creator:     creator.Creator,
			CreatorType: creator.CreatorType,
		}
	}

	// Initial metadata
	out := &v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      e.DocumentName,
		DocumentNamespace: e.DocumentNamespace,
		CreationInfo: &v2_3.CreationInfo{
			Creators: creators,
			Created:  time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: e.DocumentComment,
	}

	pkgs := make(map[int]*v2_3.Package)
	var pkgIDs []int
	dists := make(map[int]*v2_3.Package)
	var distIDs []int
	repos := make(map[int]*v2_3.Package)
	var repoIDs []int
	pkgRels := map[int][]*v2_3.Relationship{}
	for _, r := range ir.IndexRecords() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkgID, err := strconv.Atoi(r.Package.ID)
		if err != nil {
			return nil, err
		}

		pkg, ok := pkgs[pkgID]
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

			pkgs[pkgID] = pkg
			pkgIDs = append(pkgIDs, pkgID)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPkgID, err := strconv.Atoi(r.Package.Source.ID)
				if err != nil {
					return nil, err
				}

				srcPkg, ok := pkgs[srcPkgID]
				// Record the source package if we haven't seen it yet.
				if !ok {
					srcPkg = newSpdxPackageFromPackage(r.Package.Source)
					srcPkg.PrimaryPackagePurpose = "SOURCE"
					pkgs[srcPkgID] = srcPkg
					pkgIDs = append(pkgIDs, srcPkgID)
				}

				rel := &v2_3.Relationship{
					RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         v2common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				}
				pkgRels[pkgID] = append(pkgRels[pkgID], rel)
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
			distID, err := strconv.Atoi(r.Distribution.ID)
			if err != nil {
				return nil, err
			}

			dist, ok := dists[distID]
			// Record the Distribution if we haven't seen it yet.
			if !ok {
				dist = newSpdxPackageFromDistribution(r.Distribution)
				dists[distID] = dist
				distIDs = append(distIDs, distID)
			}

			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			pkgRels[pkgID] = append(pkgRels[pkgID], rel)
		}

		// Record Repositories for this package.
		if r.Repository != nil {
			repoID, err := strconv.Atoi(r.Repository.ID)
			if err != nil {
				return nil, err
			}

			repo, ok := repos[repoID]
			// Record the Repository if we haven't seen it yet.
			if !ok {
				repo = newSpdxPackageFromRepository(r.Repository)

				repos[repoID] = repo
				repoIDs = append(repoIDs, repoID)
			}

			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			pkgRels[pkgID] = append(pkgRels[pkgID], rel)
		}
	}

	// Now that we have all the data necessary to create the SPDX document,
	// we need to order it since the IndexRecords aren't in a deterministic order.
	// This is particular helpful for testing, but it wouldn't be unreasonable
	// for a user to want to diff different versions of an SPDX of the same IndexReport.
	slices.Sort(pkgIDs)
	for _, id := range pkgIDs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkg := pkgs[id]
		out.Packages = append(out.Packages, pkg)

		rels := pkgRels[id]
		slices.SortFunc(rels, cmpRelationship)
		out.Relationships = append(out.Relationships, rels...)
	}

	slices.Sort(distIDs)
	for _, id := range distIDs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		dist := dists[id]
		out.Packages = append(out.Packages, dist)
	}

	slices.Sort(repoIDs)
	for _, id := range repoIDs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		repo := repos[id]
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

// getVersion will attempt to read out the current binary's debug info, find the
// claircore version (this was copied from Clair).
func getVersion() string {
	var core string
	info, infoOK := debug.ReadBuildInfo()
	if infoOK {
		for _, m := range info.Deps {
			if m.Path != "github.com/quay/claircore" {
				continue
			}
			core = m.Version
			if m.Replace != nil && m.Replace.Version != m.Version {
				core = m.Replace.Version
			}
			return core
		}
	}

	return "unknown revision"
}
