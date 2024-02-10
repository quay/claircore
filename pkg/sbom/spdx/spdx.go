package spdx

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxtools "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/quay/claircore"
)

func ParseIndexReport(vr *claircore.IndexReport) (*spdxtools.Document, error) {
	// Initial metadata
	out := &spdxtools.Document{
		SPDXVersion:    spdxtools.Version,
		DataLicense:    spdxtools.DataLicense,
		SPDXIdentifier: "DOCUMENT",
		DocumentName:   "SPDX-claircore-" + vr.Hash.String(),
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

	for _, p := range vr.Packages {
		pkgDB := ""
		for _, e := range vr.Environments[p.ID] {
			if e.PackageDB != "" {
				pkgDB = e.PackageDB
			}
		}
		pkg := &spdxtools.Package{
			PackageName:             p.Name,
			PackageSPDXIdentifier:   common.ElementID("SPDXRef-" + p.ID),
			PackageVersion:          p.Version,
			PackageFileName:         pkgDB,
			PackageDownloadLocation: "NOASSERTION",
			FilesAnalyzed:           true,
		}
		out.Packages = append(out.Packages, pkg)
	}
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
