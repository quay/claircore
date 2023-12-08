package spdx

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxtools "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

func ParseSPDXDocument(sd *spdxtools.Document) (*claircore.IndexReport, error) {
	pkgMap := map[string]*spdxtools.Package{}
	for _, p := range sd.Packages {
		pkgMap[string(p.PackageSPDXIdentifier)] = p
	}
	digest, err := claircore.ParseDigest(sd.DocumentName)
	if err != nil {
		return nil, fmt.Errorf("cannot parse document name as a digest: %w", err)
	}
	out := &claircore.IndexReport{
		Hash:          digest,
		Repositories:  map[string]*claircore.Repository{},
		Packages:      map[string]*claircore.Package{},
		Distributions: map[string]*claircore.Distribution{},
		Environments:  map[string][]*claircore.Environment{},
		Success:       true,
	}
	for _, r := range sd.Relationships {
		aPkg := pkgMap[string(r.RefA.ElementRefID)]
		bPkg := pkgMap[string(r.RefB.ElementRefID)]

		if r.Relationship == "CONTAINED_BY" {
			if bPkg.PackageSummary == "repository" {
				// Create repository
				repo := &claircore.Repository{
					ID:   string(bPkg.PackageSPDXIdentifier),
					Name: bPkg.PackageName,
				}
				for _, er := range bPkg.PackageExternalReferences {
					switch er.RefType {
					case "cpe23Type":
						if er.Locator == "" {
							continue
						}
						repo.CPE, err = cpe.Unbind(er.Locator)
						if err != nil {
							return nil, fmt.Errorf("error unbinding repository CPE: %w", err)
						}
					case "url":
						repo.URI = er.Locator
					case "key":
						repo.Key = er.Locator
					}
				}
				out.Repositories[string(bPkg.PackageSPDXIdentifier)] = repo
				if _, ok := out.Packages[string(aPkg.PackageSPDXIdentifier)]; !ok {
					out.Packages[string(aPkg.PackageSPDXIdentifier)] = &claircore.Package{
						ID:      string(aPkg.PackageSPDXIdentifier),
						Name:    aPkg.PackageName,
						Version: aPkg.PackageVersion,
						Kind:    claircore.BINARY,
					}
				}
			}
			if bPkg.PackageSummary == "distribution" {
				if _, ok := out.Distributions[string(bPkg.PackageSPDXIdentifier)]; !ok {
					dist := &claircore.Distribution{
						ID:      string(bPkg.PackageSPDXIdentifier),
						Name:    bPkg.PackageName,
						Version: bPkg.PackageVersion,
					}
					for _, er := range bPkg.PackageExternalReferences {
						switch er.RefType {
						case "cpe23Type":
							if er.Locator == "" {
								continue
							}
							dist.CPE, err = cpe.Unbind(er.Locator)
							if err != nil {
								return nil, fmt.Errorf("error unbinding distribution CPE: %w", err)
							}
						case "did":
							dist.DID = er.Locator
						case "version_id":
							dist.VersionID = er.Locator
						case "pretty_name":
							dist.PrettyName = er.Locator
						}
					}
					out.Distributions[string(bPkg.PackageSPDXIdentifier)] = dist
				}
			}
		}
		// Make or get environment for package
		envs, ok := out.Environments[string(aPkg.PackageSPDXIdentifier)]
		if !ok {
			envs = append(envs, &claircore.Environment{
				PackageDB: aPkg.PackageFileName,
			})
		}
		if r.Relationship == "CONTAINED_BY" {
			switch bPkg.PackageSummary {
			case "layer":
				envs[0].IntroducedIn = claircore.MustParseDigest(bPkg.PackageName)
			case "repository":
				envs[0].RepositoryIDs = append(envs[0].RepositoryIDs, string(bPkg.PackageSPDXIdentifier))
			case "distribution":
				envs[0].DistributionID = string(bPkg.PackageSPDXIdentifier)
			}
		}
		out.Environments[string(aPkg.PackageSPDXIdentifier)] = envs
	}
	// Go through and add the source packages
	for _, r := range sd.Relationships {
		aPkg := pkgMap[string(r.RefA.ElementRefID)]
		bPkg := pkgMap[string(r.RefB.ElementRefID)]
		if r.Relationship == "GENERATED_FROM" {
			out.Packages[string(aPkg.PackageSPDXIdentifier)].Source = &claircore.Package{
				ID:      string(bPkg.PackageSPDXIdentifier),
				Name:    bPkg.PackageName,
				Version: bPkg.PackageVersion,
				Kind:    claircore.SOURCE,
			}
		}
	}
	return out, nil
}

func ParseIndexReport(ir *claircore.IndexReport) (*spdxtools.Document, error) {
	// Initial metadata
	out := &spdxtools.Document{
		SPDXVersion:    spdxtools.Version,
		DataLicense:    spdxtools.DataLicense,
		SPDXIdentifier: "DOCUMENT",
		DocumentName:   ir.Hash.String(),
		// This would be nice to have but don't know how we'd get context w/o
		// having to accept it as an argument.
		// DocumentNamespace: "https://clairproject.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301",
		CreationInfo: &spdxtools.CreationInfo{
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: "Claircore"},
				{CreatorType: "Organization", Creator: "Clair"},
			},
			Created: time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: fmt.Sprintf("This document was created using claircore (%s).", getVersion()),
	}

	rels := []*spdxtools.Relationship{}
	repoMap := map[string]*spdxtools.Package{}
	distMap := map[string]*spdxtools.Package{}
	pkgMap := map[string]*spdxtools.Package{}
	fmt.Println(len(ir.IndexRecords()))
	for _, r := range ir.IndexRecords() {
		fmt.Println(r.Package.Name)
		if r.Repository == nil || r.Repository.ID == "" {
			continue
		}
		pkg, ok := pkgMap[r.Package.ID]
		if !ok {
			pkgDB := ""
			for _, e := range ir.Environments[r.Package.ID] {
				if e.PackageDB != "" {
					pkgDB = e.PackageDB
				}
			}
			pkg = &spdxtools.Package{
				PackageName:             r.Package.Name,
				PackageSPDXIdentifier:   common.ElementID("pkg:" + r.Package.ID),
				PackageVersion:          r.Package.Version,
				PackageFileName:         pkgDB,
				PackageDownloadLocation: "NOASSERTION",
				FilesAnalyzed:           true,
			}
			pkgMap[r.Package.ID] = pkg
			out.Packages = append(out.Packages, pkg)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPkg := &spdxtools.Package{
					PackageName:           r.Package.Source.Name,
					PackageSPDXIdentifier: common.ElementID("src-pkg:" + r.Package.Source.ID),
					PackageVersion:        r.Package.Source.Version,
				}
				out.Packages = append(out.Packages, srcPkg)
				rels = append(rels, &spdxtools.Relationship{
					RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				})
			}
		}
		if r.Repository != nil {
			repo, ok := repoMap[r.Repository.ID]
			if !ok {
				repo = &spdxtools.Package{
					PackageName:           r.Repository.Name,
					PackageSPDXIdentifier: common.ElementID("repo:" + r.Repository.ID),
					FilesAnalyzed:         true,
					PackageSummary:        "repository",
					PackageExternalReferences: []*spdxtools.PackageExternalReference{
						{
							Category: "SECURITY",
							// TODO: always cpe:2.3?
							RefType: "cpe23Type",
							Locator: r.Repository.CPE.String(),
						},
						{
							Category: "OTHER",
							RefType:  "url",
							Locator:  r.Repository.URI,
						},
						{
							Category: "OTHER",
							RefType:  "key",
							Locator:  r.Repository.Key,
						},
					},
				}
				repoMap[r.Repository.ID] = repo
				out.Packages = append(out.Packages, repo)
			}
			rel := &spdxtools.Relationship{
				RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
		if r.Distribution != nil {
			dist, ok := distMap[r.Distribution.ID]
			if !ok {
				dist = &spdxtools.Package{
					PackageName:           r.Distribution.Name,
					PackageSPDXIdentifier: common.ElementID("dist:" + r.Distribution.ID),
					PackageVersion:        r.Distribution.Version,
					FilesAnalyzed:         true,
					PackageSummary:        "distribution",
					PackageExternalReferences: []*spdxtools.PackageExternalReference{
						{
							Category: "SECURITY",
							// TODO: always cpe:2.3?
							RefType: "cpe23Type",
							Locator: r.Distribution.CPE.String(),
						},
						{
							Category: "OTHER",
							RefType:  "did",
							Locator:  r.Distribution.DID,
						},
						{
							Category: "OTHER",
							RefType:  "version_id",
							Locator:  r.Distribution.VersionID,
						},
						{
							Category: "OTHER",
							RefType:  "pretty_name",
							Locator:  r.Distribution.PrettyName,
						},
					},
				}
				distMap[r.Distribution.ID] = dist
				out.Packages = append(out.Packages, dist)
			}
			rel := &spdxtools.Relationship{
				RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}

	layerMap := map[string]*spdxtools.Package{}
	for pkgID, envs := range ir.Environments {
		for _, e := range envs {
			pkg, ok := layerMap[e.IntroducedIn.String()]
			if !ok {
				pkg = &spdxtools.Package{
					PackageName:           e.IntroducedIn.String(),
					PackageSPDXIdentifier: common.ElementID(uuid.New().String()),
					FilesAnalyzed:         true,
					PackageSummary:        "layer",
				}
				out.Packages = append(out.Packages, pkg)
				layerMap[e.IntroducedIn.String()] = pkg
			}
			rel := &spdxtools.Relationship{
				RefA:         common.MakeDocElementID("", pkgID),
				RefB:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}
	out.Relationships = rels
	return out, nil
}

// GetVersion is copied from Clair and can hopefully give some
// context as to which revision of claircore was used.
func getVersion() string {
	info, infoOK := debug.ReadBuildInfo()
	var core string
	if infoOK {
		for _, m := range info.Deps {
			if m.Path != "github.com/quay/claircore" {
				continue
			}
			core = m.Version
			if m.Replace != nil && m.Replace.Version != m.Version {
				core = m.Replace.Version
			}
		}
	}
	if core == "" {
		core = "unknown revision"
	}
	return core
}
