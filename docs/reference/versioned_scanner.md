# Versioned Scanner
A versioned scanner is typically embedded into other scanner types.
Drives ClairCore's ability to register and understand when updaters have been changed.
Methods and functions which want to work with a generic scanner type may take a VersionedScanner interface as their arguments.

Implementors of this interface *must* providea unique name.
Making changes to an implemented scanner *must* return a new Version.
Implementors *must* return the kind: "package", "distribution", "repository"

```go
package indexer

// VersionedScanner can be embedded into specific scanner types. This allows for
// methods and functions which only need to compare names and versions of
// scanners not to require each scanner type as an argument.
type VersionedScanner interface {
	// unique name of the distribution scanner.
	Name() string
	// version of this scanner. this information will be persisted with the scan.
	Version() string
	// the kind of scanner. currently only package is implemented
	Kind() string
}
```

