# Ecosystem
An Ecosystem groups togethers scanners and coalescers which are often used together.
Ecosystems are usually defined in the package manager go package such as Dpkg. 
See /dpkg/ecosystem.go for an example.

The Indexer will retrieve artifacts from the databse scanned by the provided scanners and provide these scan artifacts to the coalescer in the Ecosystem.

```go
package indexer
// Ecosystems group together scanners and a Coalescer which are commonly used together.
//
// A typical ecosystem is "DPKG" which will use the DPKG package indexer, the "OS-Release"
// distribution scanner and the "APT" repository scanner.
//
// A Controller will scan layers with all scanners present in its configured ecosystems.
type Ecosystem struct {
	Name                 string
	PackageScanners      func(ctx context.Context) ([]PackageScanner, error)
	DistributionScanners func(ctx context.Context) ([]DistributionScanner, error)
	RepositoryScanners   func(ctx context.Context) ([]RepositoryScanner, error)
	Coalescer            func(ctx context.Context) (Coalescer, error)
}
```
