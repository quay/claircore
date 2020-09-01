# Package Scanner
A Package Scanner should discover any packages found within the given layer.
It is OK for to discover no packages within a layer.

```go
package indexer

// PackageScanner provides an interface for unique identification or a PackageScanner
// and a Scan method for extracting installed packages from an individual container layer
type PackageScanner interface {
	VersionedScanner
	// Scan performs a package scan on the given layer and returns all
	// the found packages
	Scan(context.Context, *claircore.Layer) ([]*claircore.Package, error)
}
```
