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
		pkgs = append(pkgs, &claircore.Package{
			ID:             strconv.Itoa(ii),
			Name:           fmt.Sprintf("package-%d", ii),
			Version:        fmt.Sprintf("version-%d", ii),
			Kind:           "binary",
			PackageDB:      fmt.Sprintf("package-db-%d", i),
			RepositoryHint: fmt.Sprintf("repository-hint-%d", i),
			Source: &claircore.Package{
				ID:      strconv.Itoa(n + i),
				Name:    fmt.Sprintf("source-package-%d", ii),
				Version: fmt.Sprintf("source-version-%d", ii),
				Kind:    "source",
			},
		})
	}

	return pkgs, nil
}

// GenUniquePackages creates an array of unique packages. the array is guaranteed not to have
// any duplicately named package fields. source packages are given an n + 1 ID to avoid
// duplicate primary key on insert.
func GenUniquePackages(n int) []*claircore.Package {
	pkgs := []*claircore.Package{}
	for i := 0; i < n; i++ {
		pkgs = append(pkgs, &claircore.Package{
			ID:             strconv.Itoa(i),
			Name:           fmt.Sprintf("package-%d", i),
			Version:        fmt.Sprintf("version-%d", i),
			Kind:           "binary",
			PackageDB:      fmt.Sprintf("package-db-%d", i),
			RepositoryHint: fmt.Sprintf("repository-hint-%d", i),
			Source: &claircore.Package{
				ID:      strconv.Itoa(n + i),
				Name:    fmt.Sprintf("source-package-%d", i),
				Version: fmt.Sprintf("source-version-%d", i),
				Kind:    "source",
			},
		})
	}

	return pkgs
}
