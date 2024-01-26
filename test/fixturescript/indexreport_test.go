package fixturescript

import (
	"fmt"
	"sort"
	"strings"
)

func ExampleCreateIndexReport() {
	const example = `# Sample IndexReport Fixture
Manifest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Layer    sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Repository URI=http://example.com/os-repo
Package Name=hello Version=2.12 PackageDB=bdb:var/lib/rpm
Layer    sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
PopRepository
Repository URI=http://example.com/my-repo
Package Name=bash Version=5.2.26 PackageDB=bdb:var/lib/rpm
`
	report, err := CreateIndexReport("script", strings.NewReader(example))
	if err != nil {
		panic(err)
	}
	pkgIDs := make([]string, 0, len(report.Packages))
	for id := range report.Packages {
		pkgIDs = append(pkgIDs, id)
	}
	sort.Strings(pkgIDs)
	fmt.Println("Manifest:", report.Hash)
	for _, id := range pkgIDs {
		pkg := report.Packages[id]
		fmt.Println("Package:", pkg.Name, pkg.Version)
		for _, env := range report.Environments[id] {
			fmt.Println("\tLayer:", env.IntroducedIn)
			fmt.Println("\tPackage DB:", env.PackageDB)
			fmt.Println("\tRepositories:", env.RepositoryIDs)
		}
	}
	// Output:
	// Manifest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	// Package: hello 2.12
	// 	Layer: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
	// 	Package DB: bdb:var/lib/rpm
	// 	Repositories: [0]
	// Package: bash 5.2.26
	// 	Layer: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
	// 	Package DB: bdb:var/lib/rpm
	// 	Repositories: [1]
}
