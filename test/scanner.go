package test

import (
	"fmt"

	"github.com/quay/claircore/internal/scanner"
)

// GenUniqueScanners creates n number of unique scanners. the array is gauranteed to not have
// any scanner fields be duplicates
func GenUniqueScanners(n int) scanner.VersionedScanners {
	var vscnrs = []scanner.VersionedScanner{}
	for i := 0; i < n; i++ {
		name, version, kind := fmt.Sprintf("test-scanner-%d", i), fmt.Sprintf("version-%d", i), fmt.Sprintf("kind-%d", i)
		m := scanner.NewPackageScannerMock(name, version, kind)
		vscnrs = append(vscnrs, scanner.VersionedScanner(m))
	}

	return vscnrs
}
