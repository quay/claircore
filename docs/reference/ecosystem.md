# Ecosystem
An Ecosystem groups together scanners and coalescers which are often used together.
Ecosystems are usually defined in a go package that corresponds to a package manager, such as `dpkg`. 
See `dpkg/ecosystem.go` for an example.

The Indexer will retrieve artifacts from the provided scanners and provide these scan artifacts to the coalescer in the Ecosystem.

```go
package indexer
// Ecosystems group together scanners and a Coalescer which are commonly used together.
//
// A typical ecosystem is "dpkg" which will use the dpkg package indexer, the "os-release"
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
