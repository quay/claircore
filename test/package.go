package test

import (
	"fmt"
	"strconv"

	"github.com/quay/claircore"
)

// GenDuplicatePackages creates an array of packages with duplicates. the array
// will will take n/2 and use this is a mod operand along with the current index in the for loop.
// it is  an error to set n to 0 or 1
func GenDuplicatePackages(n int) ([]*claircore.Package, error) {
	if n == 0 {
		return nil, fmt.Errorf("cannot create duplicate packages with n = 0. n must be > 1")
	}
	if n == 1 {
		return nil, fmt.Errorf("cannot create duplicate packages with n = 1, n must be > 1")
	}

	pkgs := []*claircore.Package{}
	nn := n / 2
	for i := 0; i < n; i++ {
		ii := i % nn
		pkgs = append(pkgs, createPackage(i, ii, n))
	}

	return pkgs, nil
}

// GenUniquePackages creates an array of unique packages. the array is guaranteed not to have
// any duplicately named package fields. source packages are given an n + 1 ID to avoid
// duplicate primary key on insert.
func GenUniquePackages(n int) []*claircore.Package {
	pkgs := []*claircore.Package{}
	for i := 0; i < n; i++ {
		pkgs = append(pkgs, createPackage(i, i, n))
	}

	return pkgs
}

func createPackage(i int, ii int, n int) *claircore.Package {
	return &claircore.Package{
		ID:             strconv.Itoa(ii),
		Name:           fmt.Sprintf("package-%d", ii),
		Version:        fmt.Sprintf("version-%d", ii),
		Arch:           fmt.Sprintf("arch-%d", ii),
		Kind:           claircore.BINARY,
		PackageDB:      fmt.Sprintf("package-db-%d", i),
		RepositoryHint: fmt.Sprintf("repository-hint-%d", i),
		Module:         fmt.Sprintf("module:%d", ii),
		Source: &claircore.Package{
			ID:      strconv.Itoa(n + i),
			Name:    fmt.Sprintf("source-package-%d", ii),
			Version: fmt.Sprintf("source-version-%d", ii),
			Arch:    fmt.Sprintf("source-arch-%d", ii),
			Kind:    claircore.SOURCE,
			Module:  fmt.Sprintf("source-module:%d", ii),
		},
	}
}
