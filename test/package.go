package test

import (
	"fmt"
	"strconv"

	"github.com/quay/claircore"
)

// GenDuplicatePackages creates an array of packages with duplicates.
//
// The array will will take n/2 and use this as a mod operand along with the
// current index in the for loop. It is an error to set n less than 2.
func GenDuplicatePackages(n int) ([]*claircore.Package, error) {
	if n < 2 {
		return nil, fmt.Errorf("cannot create duplicate packages with n = %d; must be > 1", n)
	}

	pkgs := []*claircore.Package{}
	nn := n / 2
	for i := range n {
		ii := i % nn
		pkgs = append(pkgs, createPackage(i, ii, n))
	}

	return pkgs, nil
}

// GenUniquePackages creates an array of unique packages.
//
// The array is guaranteed not to have any duplicated fields. Source packages
// are given an n + 1 ID to avoid duplicated primary keys on insert.
func GenUniquePackages(n int) []*claircore.Package {
	pkgs := []*claircore.Package{}
	for i := range n {
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
