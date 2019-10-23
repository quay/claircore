package test

import (
	"fmt"

	"github.com/quay/claircore/internal/scanner"
)

// GenUniquePackageScanners creates n number of unique PackageScanners. the array is gauranteed to not have
// any scanner fields be duplicates
func GenUniquePackageScanners(n int) scanner.VersionedScanners {
	var vscnrs = []scanner.VersionedScanner{}
	for i := 0; i < n; i++ {
		name, version, kind := fmt.Sprintf("test-scanner-%d", i), fmt.Sprintf("version-%d", i), fmt.Sprint("package")
		m := scanner.NewPackageScannerMock(name, version, kind)
		vscnrs = append(vscnrs, scanner.VersionedScanner(m))
	}

	return vscnrs
}

// GenUniqueDistributionScanners creates n number of unique DistributionScanners. the array is gauranteed to not have
// any scanner fields be duplicates
func GenUniqueDistributionScanners(n int) scanner.VersionedScanners {
	var vscnrs = []scanner.VersionedScanner{}
	for i := 0; i < n; i++ {
		name, version, kind := fmt.Sprintf("test-scanner-%d", i), fmt.Sprintf("version-%d", i), fmt.Sprint("distribution")
		m := scanner.NewPackageScannerMock(name, version, kind)
		vscnrs = append(vscnrs, scanner.VersionedScanner(m))
	}

	return vscnrs
}

// GenUniqueRepositoryScanners creates n number of unique RepositoryScanners. the array is gauranteed to not have
// any scanner fields be duplicates
func GenUniqueRepositoryScanners(n int) scanner.VersionedScanners {
	var vscnrs = []scanner.VersionedScanner{}
	for i := 0; i < n; i++ {
		name, version, kind := fmt.Sprintf("test-scanner-%d", i), fmt.Sprintf("version-%d", i), fmt.Sprint("repository")
		m := scanner.NewPackageScannerMock(name, version, kind)
		vscnrs = append(vscnrs, scanner.VersionedScanner(m))
	}

	return vscnrs
}
